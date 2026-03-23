//! Encrypted ratchet session state storage.
//!
//! Clients optionally back up their serialized `RatchetSession` state here,
//! encrypted client-side with a key derived from the device's private key.
//! The server stores and returns the blob verbatim — it has no ability to read,
//! validate, or modify the session state.
//!
//! ## Persistence contract
//!
//! The correct client-side procedure for atomic message send + state update:
//!
//! 1. Generate a fresh UUID v7 `batch_id`.
//! 2. Advance the ratchet and encrypt the plaintext, producing a ciphertext.
//! 3. Submit `POST /dms/{thread_id}/messages` with the `batch_id` (idempotent).
//! 4. On success, encrypt the new `RatchetSession` state and call
//!    `PUT /devices/{my_device_id}/ratchet-sessions/{peer_device_id}`.
//!
//! If a crash occurs between steps 3 and 4, the client retries step 3 on
//! recovery. The server returns success idempotently (same batch_id). The
//! client then proceeds to step 4.
//!
//! ## Optimistic locking
//!
//! Every PUT must supply the `expected_version` last read from the server. If
//! another instance of the same device wrote in the meantime, the server
//! returns 409 Conflict, and the client must re-read the current state and
//! decide how to merge before retrying.

use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::{error::AppError, extract::AuthUser, state::AppState};
use protocol::{PutRatchetSessionRequest, RatchetSessionResponse};

/// Maximum size of the encrypted state blob before base64-decoding.
/// Session state is typically ≤ 2 KiB; 64 KiB accommodates large skipped-key
/// caches with room to spare.
const MAX_ENCRYPTED_STATE_BYTES: usize = 65_536;

// ─── GET /devices/{my_device_id}/ratchet-sessions/{peer_device_id} ────────────

pub async fn get_ratchet_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((my_device_id, peer_device_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RatchetSessionResponse>, AppError> {
    verify_device_ownership(&state, my_device_id, auth.user_id).await?;

    #[derive(sqlx::FromRow)]
    struct SessionRow {
        version: i64,
        encrypted_state: String,
        updated_at: chrono::DateTime<chrono::Utc>,
    }

    let row = sqlx::query_as::<_, SessionRow>(
        "SELECT version, encrypted_state, updated_at \
         FROM ratchet_sessions \
         WHERE owner_device_id = $1 AND peer_device_id = $2",
    )
    .bind(my_device_id)
    .bind(peer_device_id)
    .fetch_optional(&state.db)
    .await?;

    match row {
        None => Err(AppError::NotFound("ratchet session not found".into())),
        Some(r) => Ok(Json(RatchetSessionResponse {
            version: r.version,
            encrypted_state: Some(r.encrypted_state),
            updated_at: r.updated_at,
        })),
    }
}

// ─── PUT /devices/{my_device_id}/ratchet-sessions/{peer_device_id} ────────────

pub async fn put_ratchet_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((my_device_id, peer_device_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<PutRatchetSessionRequest>,
) -> Result<Json<RatchetSessionResponse>, AppError> {
    verify_device_ownership(&state, my_device_id, auth.user_id).await?;

    if req.encrypted_state.is_empty() {
        return Err(AppError::BadRequest("encrypted_state must not be empty.".into()));
    }
    if req.encrypted_state.len() > MAX_ENCRYPTED_STATE_BYTES {
        return Err(AppError::BadRequest(format!(
            "encrypted_state exceeds maximum size of {} bytes.",
            MAX_ENCRYPTED_STATE_BYTES
        )));
    }
    if req.expected_version < 0 {
        return Err(AppError::BadRequest(
            "expected_version must be >= 0.".into(),
        ));
    }

    // ── Try to update an existing row ─────────────────────────────────────────
    //
    // The WHERE clause on `version = expected_version` provides optimistic
    // concurrency control. If another instance wrote in the meantime, the
    // UPDATE affects 0 rows and we fall through to the conflict / insert path.

    let updated = sqlx::query_scalar::<_, i64>(
        "UPDATE ratchet_sessions \
         SET version = version + 1, encrypted_state = $1, updated_at = NOW() \
         WHERE owner_device_id = $2 AND peer_device_id = $3 AND version = $4 \
         RETURNING version",
    )
    .bind(&req.encrypted_state)
    .bind(my_device_id)
    .bind(peer_device_id)
    .bind(req.expected_version)
    .fetch_optional(&state.db)
    .await?;

    if let Some(new_version) = updated {
        tracing::debug!(
            owner = %my_device_id,
            peer  = %peer_device_id,
            version = new_version,
            "ratchet session state updated"
        );
        let updated_at = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            "SELECT updated_at FROM ratchet_sessions \
             WHERE owner_device_id = $1 AND peer_device_id = $2",
        )
        .bind(my_device_id)
        .bind(peer_device_id)
        .fetch_one(&state.db)
        .await?;
        return Ok(Json(RatchetSessionResponse {
            version: new_version,
            encrypted_state: None,
            updated_at,
        }));
    }

    // ── 0 rows updated — either version mismatch or row doesn't exist yet ─────

    let existing_version: Option<i64> = sqlx::query_scalar(
        "SELECT version FROM ratchet_sessions \
         WHERE owner_device_id = $1 AND peer_device_id = $2",
    )
    .bind(my_device_id)
    .bind(peer_device_id)
    .fetch_optional(&state.db)
    .await?;

    if let Some(current_version) = existing_version {
        // Row exists but version doesn't match → concurrent write detected.
        tracing::debug!(
            owner = %my_device_id,
            peer  = %peer_device_id,
            expected = req.expected_version,
            current  = current_version,
            "ratchet session PUT rejected — version conflict"
        );
        return Err(AppError::Conflict(format!(
            "version conflict: expected {}, server has {}. \
             Re-read the current state and retry.",
            req.expected_version, current_version
        )));
    }

    // Row doesn't exist — only allow creation when expected_version == 0.
    if req.expected_version != 0 {
        return Err(AppError::Conflict(
            "version conflict: session not found. \
             Use expected_version = 0 to create a new session record."
                .into(),
        ));
    }

    // Verify that the peer device actually exists before inserting a FK row.
    let peer_exists: bool = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1)",
    )
    .bind(peer_device_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !peer_exists {
        return Err(AppError::NotFound(format!(
            "peer device {} not found.",
            peer_device_id
        )));
    }

    // ── INSERT new session record ──────────────────────────────────────────────

    let updated_at = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
        "INSERT INTO ratchet_sessions \
             (owner_device_id, peer_device_id, version, encrypted_state) \
         VALUES ($1, $2, 1, $3) \
         RETURNING updated_at",
    )
    .bind(my_device_id)
    .bind(peer_device_id)
    .bind(&req.encrypted_state)
    .fetch_one(&state.db)
    .await?;

    tracing::info!(
        owner = %my_device_id,
        peer  = %peer_device_id,
        "ratchet session state created"
    );

    Ok(Json(RatchetSessionResponse {
        version: 1,
        encrypted_state: None,
        updated_at,
    }))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Confirms that `device_id` belongs to `user_id`. Returns `Forbidden` if the
/// device exists but belongs to someone else, `NotFound` if the device doesn't
/// exist, and `Unauthorized` via `AuthUser` extraction if there is no session.
async fn verify_device_ownership(
    state: &AppState,
    device_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;

    match owner {
        None => Err(AppError::NotFound(format!("device {} not found.", device_id))),
        Some(id) if id != user_id => Err(AppError::Forbidden),
        _ => Ok(()),
    }
}
