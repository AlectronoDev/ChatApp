use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use uuid::Uuid;

use crate::{error::AppError, extract::AuthUser, state::AppState};
use protocol::{
    AckMessagesRequest, CreateDmRequest, CreateDmResponse, DmThreadSummary, FetchMessagesResponse,
    InboundMessage, OutboundEnvelope, SendMessageRequest, SendMessageResponse, UserSearchResult,
    X3dhInitData,
};

/// The only protocol version currently accepted. Envelopes with any other value
/// are rejected immediately so version-skew errors are caught early.
const SUPPORTED_PROTOCOL_VERSION: u8 = 1;

/// Maximum base64-encoded ciphertext length per envelope (128 KiB).
const MAX_CIPHERTEXT_BYTES: usize = 131_072;

/// Compact row returned by the thread-member-device pre-flight query.
#[derive(sqlx::FromRow)]
struct MemberDeviceRow {
    device_id: Uuid,
    signed_prekey_id: i32,
}

/// Shared row type for all message fetch queries.
#[derive(sqlx::FromRow)]
struct MessageRow {
    batch_id: Uuid,
    sender_user_id: Uuid,
    sender_device_id: Uuid,
    protocol_version: i16,
    ciphertext: String,
    x3dh_ik_dh_pub: Option<String>,
    x3dh_ek_pub: Option<String>,
    x3dh_spk_id: Option<i32>,
    x3dh_otpk_id: Option<i32>,
    created_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
}

// ─── Create or retrieve a DM thread ──────────────────────────────────────────

pub async fn create_or_get_dm(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateDmRequest>,
) -> Result<(StatusCode, Json<CreateDmResponse>), AppError> {
    if req.with_user_id == auth.user_id {
        return Err(AppError::BadRequest(
            "Cannot open a DM thread with yourself.".into(),
        ));
    }

    // Verify the target user exists.
    let target_exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)",
        req.with_user_id,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if !target_exists {
        return Err(AppError::NotFound("Target user does not exist.".into()));
    }

    // Look for an existing thread between these two users.
    let existing = sqlx::query_scalar!(
        r#"
        SELECT t.id FROM dm_threads t
        JOIN dm_thread_members m1 ON m1.thread_id = t.id AND m1.user_id = $1
        JOIN dm_thread_members m2 ON m2.thread_id = t.id AND m2.user_id = $2
        LIMIT 1
        "#,
        auth.user_id,
        req.with_user_id,
    )
    .fetch_optional(&state.db)
    .await?;

    if let Some(thread_id) = existing {
        return Ok((
            StatusCode::OK,
            Json(CreateDmResponse { thread_id, created: false }),
        ));
    }

    // Create the thread and add both members atomically.
    let mut tx = state.db.begin().await?;

    let thread_id = sqlx::query_scalar!(
        "INSERT INTO dm_threads DEFAULT VALUES RETURNING id",
    )
    .fetch_one(&mut *tx)
    .await?;

    for user_id in [auth.user_id, req.with_user_id] {
        sqlx::query!(
            "INSERT INTO dm_thread_members (thread_id, user_id) VALUES ($1, $2)",
            thread_id,
            user_id,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    tracing::info!(
        thread_id = %thread_id,
        user_a = %auth.user_id,
        user_b = %req.with_user_id,
        "DM thread created"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateDmResponse { thread_id, created: true }),
    ))
}

// ─── List DM threads for the authenticated user ───────────────────────────────

pub async fn list_dms(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<DmThreadSummary>>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT t.id AS thread_id, t.created_at,
               u.id AS other_user_id, u.username AS other_username
        FROM dm_threads t
        JOIN dm_thread_members m_self  ON m_self.thread_id  = t.id AND m_self.user_id  = $1
        JOIN dm_thread_members m_other ON m_other.thread_id = t.id AND m_other.user_id != $1
        JOIN users u ON u.id = m_other.user_id
        ORDER BY t.created_at DESC
        "#,
        auth.user_id,
    )
    .fetch_all(&state.db)
    .await?;

    let threads = rows
        .into_iter()
        .map(|r| DmThreadSummary {
            thread_id: r.thread_id,
            other_user: UserSearchResult {
                user_id: r.other_user_id,
                username: r.other_username,
            },
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(threads))
}

// ─── Send a message (multiple per-device envelopes) ───────────────────────────

pub async fn send_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(thread_id): Path<Uuid>,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, AppError> {
    // ── Batch-level size guards ───────────────────────────────────────────────

    if req.envelopes.is_empty() {
        return Err(AppError::BadRequest("At least one envelope is required.".into()));
    }
    if req.envelopes.len() > 500 {
        return Err(AppError::BadRequest(
            "Cannot send more than 500 envelopes in a single request.".into(),
        ));
    }

    // ── Per-envelope structural validation (no DB yet) ────────────────────────

    for env in &req.envelopes {
        validate_outbound_envelope(env)?;
    }

    // ── Authorization: sender is a thread member ──────────────────────────────

    let is_member = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM dm_thread_members WHERE thread_id = $1 AND user_id = $2)",
        thread_id,
        auth.user_id,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if !is_member {
        return Err(AppError::Forbidden);
    }

    // ── Authorization: sender_device_id belongs to the authenticated user ─────

    let device_owned = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND user_id = $2)",
        req.sender_device_id,
        auth.user_id,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if !device_owned {
        return Err(AppError::BadRequest(
            "sender_device_id does not belong to the authenticated user.".into(),
        ));
    }

    // ── Validate recipient devices and X3DH init consistency ─────────────────
    //
    // Fetch all devices belonging to thread members in one query. This:
    //   (a) proves every recipient_device_id belongs to a thread member, and
    //   (b) gives us each device's current signed_prekey_id so we can verify
    //       that any x3dh_init.spk_id matches the key the server actually holds.

    let member_devices: Vec<MemberDeviceRow> = sqlx::query_as(
        r#"
        SELECT d.id AS device_id, d.signed_prekey_id
        FROM devices d
        JOIN dm_thread_members m ON m.user_id = d.user_id
        WHERE m.thread_id = $1
        "#,
    )
    .bind(thread_id)
    .fetch_all(&state.db)
    .await?;

    // Map device_id → signed_prekey_id for fast per-envelope lookup.
    let device_spk_map: HashMap<Uuid, i32> = member_devices
        .into_iter()
        .map(|r| (r.device_id, r.signed_prekey_id))
        .collect();

    for env in &req.envelopes {
        let current_spk_id = device_spk_map.get(&env.recipient_device_id).ok_or_else(|| {
            AppError::BadRequest(format!(
                "recipient_device_id {} is not a device belonging to a member of this thread.",
                env.recipient_device_id,
            ))
        })?;

        // When x3dh_init is present, verify the spk_id matches the key the
        // server currently holds for the recipient device. A mismatch means the
        // initiator used a stale or invalid prekey — the responder would fail
        // to derive the same SK, making the session unrecoverable.
        if let Some(init) = &env.x3dh_init {
            if init.spk_id != *current_spk_id {
                return Err(AppError::BadRequest(format!(
                    "x3dh_init.spk_id {} does not match the current signed prekey (id {}) \
                     for device {}. Fetch a fresh key bundle and retry.",
                    init.spk_id, current_spk_id, env.recipient_device_id,
                )));
            }
        }
    }

    // ── Store all envelopes atomically ────────────────────────────────────────

    let batch_id = Uuid::now_v7();
    let created_at = chrono::Utc::now();

    let mut tx = state.db.begin().await?;

    for env in &req.envelopes {
        let envelope_id = Uuid::now_v7();
        let (ik_dh_pub, ek_pub, spk_id, otpk_id) = unpack_x3dh_init(env.x3dh_init.as_ref());
        sqlx::query(
            r#"
            INSERT INTO message_envelopes
                (id, batch_id, thread_id, sender_user_id, sender_device_id,
                 recipient_device_id, protocol_version, ciphertext,
                 x3dh_ik_dh_pub, x3dh_ek_pub, x3dh_spk_id, x3dh_otpk_id,
                 created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(envelope_id)
        .bind(batch_id)
        .bind(thread_id)
        .bind(auth.user_id)
        .bind(req.sender_device_id)
        .bind(env.recipient_device_id)
        .bind(env.protocol_version as i16)
        .bind(&env.ciphertext)
        .bind(&ik_dh_pub)
        .bind(&ek_pub)
        .bind(spk_id)
        .bind(otpk_id)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    tracing::info!(
        thread_id = %thread_id,
        sender = %auth.user_id,
        batch_id = %batch_id,
        envelopes = req.envelopes.len(),
        "DM message batch stored"
    );

    Ok(Json(SendMessageResponse { batch_id, created_at }))
}

// ─── Fetch messages for a device ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct FetchMessagesQuery {
    /// The requesting device. Must belong to the authenticated user.
    pub device_id: Uuid,
    /// Return messages with batch_id > after (poll for new messages).
    pub after: Option<Uuid>,
    /// Return messages with batch_id < before (load older history).
    pub before: Option<Uuid>,
    /// Defaults to 50, max 100.
    pub limit: Option<i64>,
}

pub async fn fetch_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(thread_id): Path<Uuid>,
    Query(params): Query<FetchMessagesQuery>,
) -> Result<Json<FetchMessagesResponse>, AppError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 100);

    let is_member = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM dm_thread_members WHERE thread_id = $1 AND user_id = $2)",
        thread_id,
        auth.user_id,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if !is_member {
        return Err(AppError::Forbidden);
    }

    let device_owned = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND user_id = $2)",
        params.device_id,
        auth.user_id,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if !device_owned {
        return Err(AppError::BadRequest(
            "device_id does not belong to the authenticated user.".into(),
        ));
    }

    // Fetch one extra row to determine whether has_more is true.
    let fetch_limit = limit + 1;

    let rows: Vec<MessageRow> = if let Some(after) = params.after {
        sqlx::query_as(
            r#"
            SELECT DISTINCT ON (batch_id)
                batch_id, sender_user_id, sender_device_id,
                protocol_version, ciphertext,
                x3dh_ik_dh_pub, x3dh_ek_pub, x3dh_spk_id, x3dh_otpk_id,
                created_at, delivered_at
            FROM message_envelopes
            WHERE thread_id = $1
              AND recipient_device_id = $2
              AND batch_id > $3
            ORDER BY batch_id ASC
            LIMIT $4
            "#,
        )
        .bind(thread_id)
        .bind(params.device_id)
        .bind(after)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?
    } else if let Some(before) = params.before {
        let mut rows: Vec<MessageRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (batch_id)
                batch_id, sender_user_id, sender_device_id,
                protocol_version, ciphertext,
                x3dh_ik_dh_pub, x3dh_ek_pub, x3dh_spk_id, x3dh_otpk_id,
                created_at, delivered_at
            FROM message_envelopes
            WHERE thread_id = $1
              AND recipient_device_id = $2
              AND batch_id < $3
            ORDER BY batch_id DESC
            LIMIT $4
            "#,
        )
        .bind(thread_id)
        .bind(params.device_id)
        .bind(before)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?;

        rows.reverse();
        rows
    } else {
        let mut rows: Vec<MessageRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (batch_id)
                batch_id, sender_user_id, sender_device_id,
                protocol_version, ciphertext,
                x3dh_ik_dh_pub, x3dh_ek_pub, x3dh_spk_id, x3dh_otpk_id,
                created_at, delivered_at
            FROM message_envelopes
            WHERE thread_id = $1
              AND recipient_device_id = $2
            ORDER BY batch_id DESC
            LIMIT $3
            "#,
        )
        .bind(thread_id)
        .bind(params.device_id)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?;

        rows.reverse();
        rows
    };

    let has_more = rows.len() as i64 > limit;
    let rows = if has_more { &rows[..limit as usize] } else { &rows[..] };

    let messages = rows.iter().map(row_to_inbound_message).collect();

    Ok(Json(FetchMessagesResponse { messages, has_more }))
}

// ─── Acknowledge delivered messages ──────────────────────────────────────────

pub async fn ack_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(thread_id): Path<Uuid>,
    Json(req): Json<AckMessagesRequest>,
) -> Result<StatusCode, AppError> {
    if req.batch_ids.is_empty() {
        return Err(AppError::BadRequest("batch_ids must not be empty.".into()));
    }
    if req.batch_ids.len() > 200 {
        return Err(AppError::BadRequest(
            "Cannot acknowledge more than 200 batches at once.".into(),
        ));
    }

    let device_owned = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND user_id = $2)",
        req.device_id,
        auth.user_id,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if !device_owned {
        return Err(AppError::BadRequest(
            "device_id does not belong to the authenticated user.".into(),
        ));
    }

    sqlx::query!(
        r#"
        UPDATE message_envelopes
        SET delivered_at = NOW()
        WHERE thread_id = $1
          AND recipient_device_id = $2
          AND batch_id = ANY($3::uuid[])
          AND delivered_at IS NULL
        "#,
        thread_id,
        req.device_id,
        &req.batch_ids as &[Uuid],
    )
    .execute(&state.db)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Validate the fields of a single outbound envelope before any DB interaction.
fn validate_outbound_envelope(env: &OutboundEnvelope) -> Result<(), AppError> {
    if env.protocol_version != SUPPORTED_PROTOCOL_VERSION {
        return Err(AppError::BadRequest(format!(
            "Unsupported protocol_version {}; only version {} is accepted.",
            env.protocol_version, SUPPORTED_PROTOCOL_VERSION,
        )));
    }

    if env.ciphertext.is_empty() {
        return Err(AppError::BadRequest("ciphertext must not be empty.".into()));
    }
    if env.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(AppError::BadRequest(
            "Individual envelope ciphertext must not exceed 128 KB.".into(),
        ));
    }

    if let Some(init) = &env.x3dh_init {
        validate_x3dh_init(init, env.recipient_device_id)?;
    }

    Ok(())
}

/// Validate the key fields inside an X3DH init block.
fn validate_x3dh_init(init: &X3dhInitData, device_id: Uuid) -> Result<(), AppError> {
    crypto_core::decode_x25519_pubkey(&init.ik_dh_pub).map_err(|_| {
        AppError::BadRequest(format!(
            "x3dh_init.ik_dh_pub for device {device_id} is not a valid \
             base64-encoded 32-byte X25519 public key."
        ))
    })?;

    crypto_core::decode_x25519_pubkey(&init.ek_pub).map_err(|_| {
        AppError::BadRequest(format!(
            "x3dh_init.ek_pub for device {device_id} is not a valid \
             base64-encoded 32-byte X25519 public key."
        ))
    })?;

    Ok(())
}

/// Decompose an optional `X3dhInitData` reference into four nullable DB columns.
fn unpack_x3dh_init(
    init: Option<&X3dhInitData>,
) -> (Option<String>, Option<String>, Option<i32>, Option<i32>) {
    match init {
        Some(i) => (
            Some(i.ik_dh_pub.clone()),
            Some(i.ek_pub.clone()),
            Some(i.spk_id),
            i.otpk_id,
        ),
        None => (None, None, None, None),
    }
}

/// Build an `InboundMessage` from a fetched database row.
fn row_to_inbound_message(r: &MessageRow) -> InboundMessage {
    let x3dh_init = match (&r.x3dh_ik_dh_pub, &r.x3dh_ek_pub, r.x3dh_spk_id) {
        (Some(ik), Some(ek), Some(spk_id)) => Some(X3dhInitData {
            ik_dh_pub: ik.clone(),
            ek_pub: ek.clone(),
            spk_id,
            otpk_id: r.x3dh_otpk_id,
        }),
        _ => None,
    };

    InboundMessage {
        batch_id: r.batch_id,
        sender_user_id: r.sender_user_id,
        sender_device_id: r.sender_device_id,
        protocol_version: r.protocol_version as u8,
        ciphertext: r.ciphertext.clone(),
        x3dh_init,
        created_at: r.created_at,
        delivered_at: r.delivered_at,
    }
}
