use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use rand::RngCore;
use subtle::ConstantTimeEq;

use crate::{
    error::AppError,
    extract::{sha256_hex, AuthUser},
    state::AppState,
};
use protocol::{
    LoginRequest, LoginResponse, RecoverRequest, RecoverResponse, SignupRequest, SignupResponse,
    UserProfile,
};

/// Maximum active (non-revoked, non-expired) sessions allowed per user.
/// When the limit is reached, the caller must sign out of an existing session
/// before they can sign in again. This prevents unbounded session accumulation
/// from repeated logins without logout.
const MAX_CONCURRENT_SESSIONS: i64 = 10;

// ─── Signup ───────────────────────────────────────────────────────────────────

pub async fn signup(
    State(state): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Result<(StatusCode, Json<SignupResponse>), AppError> {
    validate_username(&req.username)?;
    validate_password(&req.password)?;

    // Rate-limit signup attempts per target username to slow mass account
    // creation and username-squatting hammers.
    if state.auth_rate_limiter.check_key(&req.username).is_err() {
        crate::audit::auth_rate_limited(&req.username, "signup");
        return Err(AppError::TooManyRequests);
    }

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

    crate::audit::auth_signup(user_id, &req.username);

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
    // ── Rate limit ────────────────────────────────────────────────────────────
    //
    // Applied before any DB work so a brute-force loop is throttled as early
    // as possible. Keyed by username so an attack against one account does not
    // exhaust quota for others.
    if state.auth_rate_limiter.check_key(&req.username).is_err() {
        crate::audit::auth_rate_limited(&req.username, "login");
        return Err(AppError::TooManyRequests);
    }

    // ── Lookup and verify ─────────────────────────────────────────────────────
    //
    // Return Unauthorized regardless of whether the username exists to prevent
    // account enumeration via differing error codes.
    let user = sqlx::query!(
        "SELECT id, username, password_hash FROM users WHERE username = $1",
        req.username,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Unauthorized)?;

    let password_valid = verify_password(req.password, user.password_hash).await?;
    if !password_valid {
        crate::audit::auth_login_failure(&req.username, "bad_credentials");
        return Err(AppError::Unauthorized);
    }

    // ── Session cap ───────────────────────────────────────────────────────────
    //
    // Prevents unbounded session accumulation from repeated logins without
    // logout. The check runs after successful auth so an unauthenticated probe
    // cannot infer whether an account has reached its session limit.
    let session_count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sessions \
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    if session_count >= MAX_CONCURRENT_SESSIONS {
        crate::audit::auth_login_session_cap(user.id, session_count);
        return Err(AppError::BadRequest(format!(
            "Maximum of {MAX_CONCURRENT_SESSIONS} concurrent sessions reached. \
             Sign out of an existing session first."
        )));
    }

    // ── Issue session ─────────────────────────────────────────────────────────

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

    crate::audit::auth_login_success(user.id);

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

    crate::audit::auth_logout(auth.user_id, auth.session_id);

    Ok(StatusCode::NO_CONTENT)
}

// ─── Recover ──────────────────────────────────────────────────────────────────

pub async fn recover(
    State(state): State<AppState>,
    Json(req): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, AppError> {
    // ── Security invariant: recovery ≠ device key recovery ───────────────────
    //
    // Account recovery grants a new session token and a new account password.
    // It does NOT restore any device private keys, ratchet session states, or
    // historical ciphertext. Old message history is permanently inaccessible
    // after a device is lost — this is by design (forward secrecy guarantee).
    // The recovered account can only read NEW messages on NEW devices going
    // forward.

    validate_password(&req.new_password)?;

    // Rate-limit recovery attempts per username to slow recovery-code guessing.
    // Although a 128-bit random code makes guessing computationally infeasible,
    // limiting attempts is defence in depth.
    if state.auth_rate_limiter.check_key(&req.username).is_err() {
        crate::audit::auth_rate_limited(&req.username, "recover");
        return Err(AppError::TooManyRequests);
    }

    let user = sqlx::query!(
        "SELECT id, recovery_code_hash FROM users WHERE username = $1",
        req.username,
    )
    .fetch_optional(&state.db)
    .await?
    // Return the same error whether the username exists or not to prevent
    // account enumeration.
    .ok_or(AppError::Unauthorized)?;

    // Constant-time comparison of the SHA-256 hex hashes prevents timing
    // side-channels that could otherwise leak partial information about the
    // stored hash to an attacker who can measure response latency.
    let submitted_hash = sha256_hex(&req.recovery_code);
    let code_valid = bool::from(
        submitted_hash
            .as_bytes()
            .ct_eq(user.recovery_code_hash.as_bytes()),
    );
    if !code_valid {
        crate::audit::auth_recover_failure(&req.username, "bad_recovery_code");
        return Err(AppError::Unauthorized);
    }

    let new_password_hash = hash_password(req.new_password).await?;
    let (new_recovery_code, new_recovery_code_hash) = generate_recovery_code();
    let (token, token_hash) = generate_session_token();
    let expires_at = Utc::now() + chrono::Duration::days(state.config.session_duration_days);

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

    // Revoke ALL existing sessions: if the account was compromised, the
    // attacker's session(s) are immediately invalidated. The caller receives
    // a fresh session below.
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

    crate::audit::auth_recover_success(user.id);

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
            "Username must be 3-32 characters.".into(),
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
    // Upper bound prevents Argon2 DoS via arbitrarily long inputs. Passwords
    // longer than 128 bytes provide no practical security improvement.
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
///
/// Parameters (argon2 crate v0.5 defaults, OWASP-compliant option 2):
///   algorithm  : Argon2id (hybrid, resistant to side-channel and GPU attacks)
///   version    : 0x13 (19, current)
///   memory     : 19 456 KiB (19 MiB)  ≥ OWASP minimum of 19 MiB
///   iterations : 2                    ≥ OWASP minimum for 19 MiB
///   parallelism: 1
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
/// Format: `XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX` (32 uppercase hex chars,
/// 128 bits of entropy — makes guessing computationally infeasible).
fn generate_recovery_code() -> (String, String) {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let h = hex::encode(bytes).to_uppercase();
    let code = format!("{}-{}-{}-{}", &h[0..8], &h[8..16], &h[16..24], &h[24..32]);
    let hash = sha256_hex(&code);
    (code, hash)
}
