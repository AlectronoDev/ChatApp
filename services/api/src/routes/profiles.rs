use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use crate::{error::AppError, extract::AuthUser, state::AppState};
use protocol::{DeleteAccountRequest, PublicProfile, UpdateProfileRequest};

// ─── GET /users/{username}/profile ───────────────────────────────────────────

pub async fn get_profile(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(username): Path<String>,
) -> Result<Json<PublicProfile>, AppError> {
    let row = sqlx::query!(
        r#"
        SELECT u.id, u.username, p.display_name, p.bio, p.avatar_url
        FROM users u
        LEFT JOIN user_profiles p ON p.user_id = u.id
        WHERE u.username = $1
        "#,
        username,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("User '{username}' not found.")))?;

    Ok(Json(PublicProfile {
        user_id: row.id,
        username: row.username,
        display_name: row.display_name,
        bio: row.bio,
        avatar_url: row.avatar_url,
    }))
}

// ─── PATCH /users/me/profile ──────────────────────────────────────────────────

pub async fn update_profile(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<PublicProfile>, AppError> {
    if let Some(ref name) = req.display_name {
        if name.len() > 64 {
            return Err(AppError::BadRequest(
                "Display name must be 64 characters or fewer.".into(),
            ));
        }
    }
    if let Some(ref bio) = req.bio {
        if bio.len() > 200 {
            return Err(AppError::BadRequest(
                "Bio must be 200 characters or fewer.".into(),
            ));
        }
    }
    if let Some(ref url) = req.avatar_url {
        if url.len() > 512 {
            return Err(AppError::BadRequest(
                "Avatar URL must be 512 characters or fewer.".into(),
            ));
        }
    }

    // Upsert the profile row and return the final stored values in one round-trip.
    let row = sqlx::query!(
        r#"
        INSERT INTO user_profiles (user_id, display_name, bio, avatar_url, updated_at)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (user_id) DO UPDATE
            SET display_name = EXCLUDED.display_name,
                bio          = EXCLUDED.bio,
                avatar_url   = EXCLUDED.avatar_url,
                updated_at   = NOW()
        RETURNING display_name, bio, avatar_url
        "#,
        auth.user_id,
        req.display_name,
        req.bio,
        req.avatar_url,
    )
    .fetch_one(&state.db)
    .await?;

    tracing::info!(user_id = %auth.user_id, "profile updated");

    Ok(Json(PublicProfile {
        user_id: auth.user_id,
        username: auth.username,
        display_name: row.display_name,
        bio: row.bio,
        avatar_url: row.avatar_url,
    }))
}

// ─── DELETE /users/me ────────────────────────────────────────────────────────

pub async fn delete_account(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<StatusCode, AppError> {
    let user = sqlx::query!(
        "SELECT password_hash FROM users WHERE id = $1",
        auth.user_id,
    )
    .fetch_one(&state.db)
    .await?;

    let password_valid = verify_password(req.password, user.password_hash).await?;
    if !password_valid {
        return Err(AppError::Unauthorized);
    }

    // ON DELETE CASCADE on sessions, devices, dm_thread_members, server_members,
    // message_envelopes, channel_envelopes, and user_profiles all flow from
    // the users row — a single DELETE is sufficient.
    sqlx::query!("DELETE FROM users WHERE id = $1", auth.user_id)
        .execute(&state.db)
        .await?;

    tracing::info!(user_id = %auth.user_id, username = %auth.username, "account permanently deleted");

    Ok(StatusCode::NO_CONTENT)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn verify_password(password: String, stored_hash: String) -> Result<bool, AppError> {
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&stored_hash)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("invalid hash format: {e}")))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("spawn_blocking panicked: {e}")))?
}
