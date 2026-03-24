//! Structured audit events for all security-sensitive operations.
//!
//! ## Invariants
//!
//! Audit events MUST NEVER include:
//! - Passwords or password hashes
//! - Session tokens (raw or hashed)
//! - Recovery codes (raw or hashed)
//! - Private cryptographic key material (X25519 scalars, Ed25519 signing keys)
//! - AEAD nonces or message plaintext
//! - Full stack traces or internal error messages (those go to `tracing::error!`)
//!
//! Audit events MAY include:
//! - User IDs and device IDs (UUIDs — non-secret identifiers)
//! - Usernames (public account identifier)
//! - Outcome ("success" or reason for failure in generic terms)
//! - Epoch numbers, member counts, key counts (structural, non-secret)
//!
//! ## Log format
//!
//! Every event carries a dot-namespaced `event` field (e.g. `auth.login.success`)
//! so operators can filter, alert, and ship events to a SIEM with simple
//! field-based rules rather than parsing free-form log messages.
//!
//! Successful sensitive operations use `tracing::info!`.
//! Failures and suspicious activity use `tracing::warn!`.

use uuid::Uuid;

// ─── Auth ─────────────────────────────────────────────────────────────────────

/// A new account was created.
pub fn auth_signup(user_id: Uuid, username: &str) {
    tracing::info!(
        event    = "auth.signup",
        %user_id,
        username,
        "account created"
    );
}

/// A login or signup or recovery attempt was blocked by rate limiting.
pub fn auth_rate_limited(username: &str, endpoint: &str) {
    tracing::warn!(
        event    = "auth.rate_limited",
        username,
        endpoint,
        "auth endpoint rate limit exceeded"
    );
}

/// A login attempt succeeded and a new session was issued.
pub fn auth_login_success(user_id: Uuid) {
    tracing::info!(
        event    = "auth.login.success",
        %user_id,
        "login succeeded"
    );
}

/// A login attempt failed (wrong password or unknown username).
/// The `reason` field uses a generic category — never include the internal
/// error or whether the username actually exists.
pub fn auth_login_failure(username: &str, reason: &str) {
    tracing::warn!(
        event    = "auth.login.failure",
        username,
        reason,
        "login failed"
    );
}

/// Login was rejected because the user reached the concurrent session cap.
pub fn auth_login_session_cap(user_id: Uuid, session_count: i64) {
    tracing::warn!(
        event         = "auth.login.session_cap",
        %user_id,
        session_count,
        "login rejected: concurrent session cap reached"
    );
}

/// A session was explicitly revoked (logout).
pub fn auth_logout(user_id: Uuid, session_id: Uuid) {
    tracing::info!(
        event      = "auth.logout",
        %user_id,
        %session_id,
        "session revoked"
    );
}

/// Account recovery succeeded: password rotated, all old sessions revoked.
pub fn auth_recover_success(user_id: Uuid) {
    tracing::info!(
        event    = "auth.recover.success",
        %user_id,
        "account recovered via recovery code"
    );
}

/// Account recovery failed (wrong recovery code or unknown username).
pub fn auth_recover_failure(username: &str, reason: &str) {
    tracing::warn!(
        event    = "auth.recover.failure",
        username,
        reason,
        "account recovery failed"
    );
}

// ─── Devices ──────────────────────────────────────────────────────────────────

/// A new device (with its key bundle) was registered to an account.
pub fn device_registered(user_id: Uuid, device_id: Uuid, prekey_count: usize) {
    tracing::info!(
        event         = "device.registered",
        %user_id,
        %device_id,
        prekey_count,
        "device registered"
    );
}

/// A device was removed from an account.
pub fn device_deleted(user_id: Uuid, device_id: Uuid) {
    tracing::info!(
        event    = "device.deleted",
        %user_id,
        %device_id,
        "device deleted"
    );
}

// ─── Key bundles (X3DH) ───────────────────────────────────────────────────────

/// An authenticated user fetched the X3DH key bundles for a target user.
/// Logged at INFO so operators can correlate OTPK depletion with requesters.
pub fn keys_bundle_fetched(requester_id: Uuid, target_username: &str, bundle_count: usize) {
    tracing::info!(
        event            = "keys.bundle_fetched",
        %requester_id,
        target_username,
        bundle_count,
        "X3DH key bundle fetched"
    );
}

/// A key-bundle fetch was blocked by rate limiting.
pub fn keys_bundle_rate_limited(requester_id: Uuid, target_username: &str) {
    tracing::warn!(
        event           = "keys.bundle_rate_limited",
        %requester_id,
        target_username,
        "X3DH key bundle fetch rate limited"
    );
}

// ─── MLS ─────────────────────────────────────────────────────────────────────

/// A new MLS group was initialized for a channel.
pub fn mls_group_initialized(
    group_id: Uuid,
    channel_id: Uuid,
    creator_device_id: Uuid,
    member_count: usize,
) {
    tracing::info!(
        event             = "mls.group.initialized",
        %group_id,
        %channel_id,
        %creator_device_id,
        member_count,
        "MLS group initialized"
    );
}

/// A Commit was accepted, advancing the group to a new epoch.
pub fn mls_commit_accepted(
    group_id: Uuid,
    sender_device_id: Uuid,
    old_epoch: i64,
    new_epoch: i64,
    new_member_count: usize,
) {
    tracing::info!(
        event             = "mls.commit.accepted",
        %group_id,
        %sender_device_id,
        old_epoch,
        new_epoch,
        new_member_count,
        "MLS Commit accepted"
    );
}

/// A Commit was rejected (stale epoch, non-member sender, or size violation).
pub fn mls_commit_rejected(group_id: Uuid, sender_device_id: Uuid, reason: &str) {
    tracing::warn!(
        event             = "mls.commit.rejected",
        %group_id,
        %sender_device_id,
        reason,
        "MLS Commit rejected"
    );
}
