use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use rand::RngCore;

use crate::{
    error::AppError,
    extract::{sha256_hex, AuthUser},
    state::AppState,
};
use protocol::{
    LoginRequest, LoginResponse, RecoverRequest, RecoverResponse, SignupRequest, SignupResponse,
    UserProfile,
};

// ─── Signup ───────────────────────────────────────────────────────────────────

pub async fn signup(
    State(state): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Result<(StatusCode, Json<SignupResponse>), AppError> {
    validate_username(&req.username)?;
    validate_password(&req.password)?;

    let password_hash = hash_password(req.password).await?;
    let (recovery_code, recovery_code_hash) = generate_recovery_code();
    let (token, token_hash) = generate_session_token();
    let expires_at = Utc::now() + chrono::Duration::days(state.config.session_duration_days);

    let user_id = sqlx::query_scalar!(
        "INSERT INTO users (username, password_hash, recovery_code_hash)
         VALUES ($1, $2, $3)
         RETURNING id",
        req.username,
        password_hash,
        recovery_code_hash,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.constraint() == Some("users_username_key") => {
            AppError::Conflict("Username is already taken.".into())
        }
        _ => AppError::Internal(e.into()),
    })?;

    sqlx::query!(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        user_id,
        token_hash,
        expires_at,
    )
    .execute(&state.db)
    .await?;

    tracing::info!(user_id = %user_id, username = %req.username, "new account created");

    Ok((
        StatusCode::CREATED,
        Json(SignupResponse {
            user_id,
            username: req.username,
            recovery_code,
            token,
            expires_at,
        }),
    ))
}

// ─── Login ────────────────────────────────────────────────────────────────────

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let user = sqlx::query!(
        "SELECT id, username, password_hash FROM users WHERE username = $1",
        req.username,
    )
    .fetch_optional(&state.db)
    .await?
    // Return the same error whether the username exists or not to prevent
    // username enumeration.
    .ok_or(AppError::Unauthorized)?;

    let password_valid = verify_password(req.password, user.password_hash).await?;
    if !password_valid {
        return Err(AppError::Unauthorized);
    }

    let (token, token_hash) = generate_session_token();
    let expires_at = Utc::now() + chrono::Duration::days(state.config.session_duration_days);

    sqlx::query!(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        user.id,
        token_hash,
        expires_at,
    )
    .execute(&state.db)
    .await?;

    tracing::info!(user_id = %user.id, "login successful");

    Ok(Json(LoginResponse {
        user_id: user.id,
        username: user.username,
        token,
        expires_at,
    }))
}

// ─── Logout ───────────────────────────────────────────────────────────────────

pub async fn logout(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    sqlx::query!(
        "UPDATE sessions SET revoked_at = NOW() WHERE id = $1",
        auth.session_id,
    )
    .execute(&state.db)
    .await?;

    tracing::info!(user_id = %auth.user_id, session_id = %auth.session_id, "session revoked");

    Ok(StatusCode::NO_CONTENT)
}

// ─── Recover ──────────────────────────────────────────────────────────────────

pub async fn recover(
    State(state): State<AppState>,
    Json(req): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, AppError> {
    validate_password(&req.new_password)?;

    let user = sqlx::query!(
        "SELECT id, recovery_code_hash FROM users WHERE username = $1",
        req.username,
    )
    .fetch_optional(&state.db)
    .await?
    // Same error regardless of whether the username exists, to prevent enumeration.
    .ok_or(AppError::Unauthorized)?;

    // Recovery codes are high-entropy random tokens, so SHA-256 comparison is
    // sufficient here (no need for Argon2id).
    let submitted_hash = sha256_hex(&req.recovery_code);
    if submitted_hash != user.recovery_code_hash {
        return Err(AppError::Unauthorized);
    }

    let new_password_hash = hash_password(req.new_password).await?;
    let (new_recovery_code, new_recovery_code_hash) = generate_recovery_code();
    let (token, token_hash) = generate_session_token();
    let expires_at = Utc::now() + chrono::Duration::days(30);

    let mut tx = state.db.begin().await?;

    // Rotate both the password and the recovery code atomically. The old
    // recovery code is immediately invalidated.
    sqlx::query!(
        "UPDATE users SET password_hash = $1, recovery_code_hash = $2 WHERE id = $3",
        new_password_hash,
        new_recovery_code_hash,
        user.id,
    )
    .execute(&mut *tx)
    .await?;

    // Revoke all existing sessions since the password was reset.
    sqlx::query!(
        "UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
        user.id,
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        user.id,
        token_hash,
        expires_at,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(user_id = %user.id, "account recovered via recovery code");

    Ok(Json(RecoverResponse {
        new_recovery_code,
        token,
        expires_at,
    }))
}

// ─── Me ───────────────────────────────────────────────────────────────────────

pub async fn me(auth: AuthUser) -> Json<UserProfile> {
    Json(UserProfile {
        user_id: auth.user_id,
        username: auth.username,
    })
}

// ─── Validation helpers ───────────────────────────────────────────────────────

fn validate_username(username: &str) -> Result<(), AppError> {
    let len = username.len();
    if len < 3 || len > 32 {
        return Err(AppError::BadRequest(
            "Username must be 3–32 characters.".into(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
    {
        return Err(AppError::BadRequest(
            "Username may only contain lowercase letters, digits, underscores, and dots.".into(),
        ));
    }
    if username.starts_with(['.', '_']) || username.ends_with(['.', '_']) {
        return Err(AppError::BadRequest(
            "Username cannot start or end with '.' or '_'.".into(),
        ));
    }
    if username.contains("..") || username.contains("__") {
        return Err(AppError::BadRequest(
            "Username cannot contain consecutive '.' or '_'.".into(),
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters.".into(),
        ));
    }
    if password.len() > 128 {
        return Err(AppError::BadRequest(
            "Password must not exceed 128 characters.".into(),
        ));
    }
    Ok(())
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

/// Hash a password with Argon2id. Runs in a blocking thread to avoid
/// stalling the async runtime during the intentionally expensive hash.
async fn hash_password(password: String) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| AppError::Internal(anyhow::anyhow!("password hashing failed: {e}")))
    })
    .await
    .map_err(|e| AppError::Internal(anyhow::anyhow!("spawn_blocking panicked: {e}")))?
}

/// Verify a password against a stored Argon2id hash. Runs in a blocking thread.
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

/// Generate a cryptographically random bearer token and return both the raw
/// token (sent to the client) and its SHA-256 hex hash (stored in the DB).
fn generate_session_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    let hash = sha256_hex(&token);
    (token, hash)
}

/// Generate a human-readable one-time recovery code and its SHA-256 hash.
/// Format: `XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX` (32 uppercase hex chars).
fn generate_recovery_code() -> (String, String) {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let h = hex::encode(bytes).to_uppercase();
    let code = format!("{}-{}-{}-{}", &h[0..8], &h[8..16], &h[16..24], &h[24..32]);
    let hash = sha256_hex(&code);
    (code, hash)
}

