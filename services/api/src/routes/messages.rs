use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::{error::AppError, extract::AuthUser, state::AppState};

/// Shared row type for all message fetch queries. Using a named struct with
/// sqlx::FromRow lets the three pagination branches share the same return type.
#[derive(sqlx::FromRow)]
struct MessageRow {
    batch_id: Uuid,
    sender_user_id: Uuid,
    sender_device_id: Uuid,
    ciphertext: String,
    created_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
}
use protocol::{
    AckMessagesRequest, CreateDmRequest, CreateDmResponse, DmThreadSummary, FetchMessagesResponse,
    InboundMessage, SendMessageRequest, SendMessageResponse, UserSearchResult,
};

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
    if req.envelopes.is_empty() {
        return Err(AppError::BadRequest("At least one envelope is required.".into()));
    }
    if req.envelopes.len() > 500 {
        return Err(AppError::BadRequest(
            "Cannot send more than 500 envelopes in a single request.".into(),
        ));
    }
    for env in &req.envelopes {
        if env.ciphertext.len() > 131_072 {
            return Err(AppError::BadRequest(
                "Individual envelope ciphertext must not exceed 128 KB.".into(),
            ));
        }
    }

    // Verify the sender is a member of this thread.
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

    // Verify sender_device_id belongs to the authenticated user.
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

    let batch_id = Uuid::now_v7();
    let created_at = chrono::Utc::now();

    let mut tx = state.db.begin().await?;

    for env in &req.envelopes {
        let envelope_id = Uuid::now_v7();
        sqlx::query!(
            r#"
            INSERT INTO message_envelopes
                (id, batch_id, thread_id, sender_user_id, sender_device_id,
                 recipient_device_id, ciphertext, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            envelope_id,
            batch_id,
            thread_id,
            auth.user_id,
            req.sender_device_id,
            env.recipient_device_id,
            env.ciphertext,
            created_at,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    tracing::info!(
        thread_id = %thread_id,
        sender = %auth.user_id,
        batch_id = %batch_id,
        envelopes = req.envelopes.len(),
        "message batch stored"
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

    // Verify the user is a thread member and the device belongs to the user.
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
        // Poll for new messages (ascending order from cursor).
        sqlx::query_as(
            r#"
            SELECT DISTINCT ON (batch_id)
                batch_id, sender_user_id, sender_device_id,
                ciphertext, created_at, delivered_at
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
        // Load older history (descending from cursor, then reverse for display order).
        let mut rows: Vec<MessageRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (batch_id)
                batch_id, sender_user_id, sender_device_id,
                ciphertext, created_at, delivered_at
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
        // Most recent messages (descending, then reverse for chronological display).
        let mut rows: Vec<MessageRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (batch_id)
                batch_id, sender_user_id, sender_device_id,
                ciphertext, created_at, delivered_at
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

    let messages = rows
        .iter()
        .map(|r| InboundMessage {
            batch_id: r.batch_id,
            sender_user_id: r.sender_user_id,
            sender_device_id: r.sender_device_id,
            ciphertext: r.ciphertext.clone(),
            created_at: r.created_at,
            delivered_at: r.delivered_at,
        })
        .collect();

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

    // Verify device belongs to the user.
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
