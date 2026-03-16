use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::{error::AppError, extract::AuthUser, state::AppState};
use protocol::{
    AckMessagesRequest, FetchMessagesResponse, InboundMessage, SendMessageRequest,
    SendMessageResponse,
};

/// Named row type so all three pagination branches share the same return type.
#[derive(sqlx::FromRow)]
struct ChannelMessageRow {
    batch_id: Uuid,
    sender_user_id: Uuid,
    sender_device_id: Uuid,
    ciphertext: String,
    created_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
}

// ─── Send a message to a channel ─────────────────────────────────────────────

pub async fn send_channel_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
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

    // The sender must be a member of the server that owns this channel.
    let is_member = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM server_members sm
            JOIN channels c ON c.server_id = sm.server_id
            WHERE c.id = $1 AND sm.user_id = $2
        )
        "#,
        channel_id,
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
            INSERT INTO channel_envelopes
                (id, batch_id, channel_id, sender_user_id, sender_device_id,
                 recipient_device_id, ciphertext, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            envelope_id,
            batch_id,
            channel_id,
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
        channel_id = %channel_id,
        sender = %auth.user_id,
        batch_id = %batch_id,
        envelopes = req.envelopes.len(),
        "channel message batch stored"
    );

    Ok(Json(SendMessageResponse { batch_id, created_at }))
}

// ─── Fetch messages for a device ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct FetchChannelMessagesQuery {
    pub device_id: Uuid,
    pub after: Option<Uuid>,
    pub before: Option<Uuid>,
    pub limit: Option<i64>,
}

pub async fn fetch_channel_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<FetchChannelMessagesQuery>,
) -> Result<Json<FetchMessagesResponse>, AppError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 100);

    let is_member = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM server_members sm
            JOIN channels c ON c.server_id = sm.server_id
            WHERE c.id = $1 AND sm.user_id = $2
        )
        "#,
        channel_id,
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

    let fetch_limit = limit + 1;

    let rows: Vec<ChannelMessageRow> = if let Some(after) = params.after {
        sqlx::query_as(
            r#"
            SELECT DISTINCT ON (batch_id)
                batch_id, sender_user_id, sender_device_id,
                ciphertext, created_at, delivered_at
            FROM channel_envelopes
            WHERE channel_id = $1
              AND recipient_device_id = $2
              AND batch_id > $3
            ORDER BY batch_id ASC
            LIMIT $4
            "#,
        )
        .bind(channel_id)
        .bind(params.device_id)
        .bind(after)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?
    } else if let Some(before) = params.before {
        let mut rows: Vec<ChannelMessageRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (batch_id)
                batch_id, sender_user_id, sender_device_id,
                ciphertext, created_at, delivered_at
            FROM channel_envelopes
            WHERE channel_id = $1
              AND recipient_device_id = $2
              AND batch_id < $3
            ORDER BY batch_id DESC
            LIMIT $4
            "#,
        )
        .bind(channel_id)
        .bind(params.device_id)
        .bind(before)
        .bind(fetch_limit)
        .fetch_all(&state.db)
        .await?;

        rows.reverse();
        rows
    } else {
        let mut rows: Vec<ChannelMessageRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (batch_id)
                batch_id, sender_user_id, sender_device_id,
                ciphertext, created_at, delivered_at
            FROM channel_envelopes
            WHERE channel_id = $1
              AND recipient_device_id = $2
            ORDER BY batch_id DESC
            LIMIT $3
            "#,
        )
        .bind(channel_id)
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

pub async fn ack_channel_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
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
        UPDATE channel_envelopes
        SET delivered_at = NOW()
        WHERE channel_id = $1
          AND recipient_device_id = $2
          AND batch_id = ANY($3::uuid[])
          AND delivered_at IS NULL
        "#,
        channel_id,
        req.device_id,
        &req.batch_ids as &[Uuid],
    )
    .execute(&state.db)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}
