//! MLS Delivery Service (DS) routes.
//!
//! The server is a pure delivery service (RFC 9420 §4): it stores and
//! fans out opaque TLS-encoded MLS blobs without parsing their internals.
//! All cryptographic operations (ratchet trees, epoch key schedules, group
//! secrets) run exclusively on client devices.
//!
//! Security invariants enforced server-side:
//! - Epoch monotonicity: only one Commit per epoch wins; concurrent submitters
//!   receive 409 Conflict.
//! - Member-list integrity: the DS delivers messages only to devices in the
//!   current member list, updated atomically with each accepted Commit.
//! - KeyPackage single-use: each KeyPackage is consumed exactly once (like
//!   one-time prekeys in X3DH).
//! - Blob size bounds: all opaque payloads are checked for size before storage.
//! - Device ownership: all mutating calls verify the device belongs to the
//!   authenticated user.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use protocol::{
    ClaimMlsKeyPackagesResponse, FetchMlsMessagesResponse, FetchMlsWelcomesResponse,
    InitMlsGroupRequest, InitMlsGroupResponse, MlsGroupInfo, MlsInboundMessage,
    MlsKeyPackageClaim, MlsPendingWelcome, SendMlsMessageRequest, SubmitMlsCommitRequest,
    SubmitMlsCommitResponse, UploadMlsKeyPackagesRequest,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{error::AppError, extract::AuthUser, state::AppState};
use crypto_core::mls::{
    validate_mls_blob, MAX_KEY_PACKAGES_PER_UPLOAD, MAX_KEY_PACKAGE_B64_BYTES,
    MAX_MLS_MESSAGE_B64_BYTES, MAX_WELCOME_B64_BYTES, MIN_KEY_PACKAGES_PER_UPLOAD,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Hard limit on the number of members in an MLS group.
/// Prevents pathologically large Commit messages and member-list scans.
const MAX_GROUP_MEMBERS: usize = 500;

/// Maximum number of Welcome messages that can be included in a single Commit.
const MAX_WELCOMES_PER_COMMIT: usize = 50;

/// Default page size for `fetch_mls_messages`.
const DEFAULT_MESSAGE_PAGE: i64 = 50;

/// Maximum page size for `fetch_mls_messages`.
const MAX_MESSAGE_PAGE: i64 = 200;

// ─── KeyPackage management ────────────────────────────────────────────────────

/// `POST /devices/{device_id}/mls-key-packages`
///
/// Upload a batch of MLS KeyPackages for this device. KeyPackages are consumed
/// one-at-a-time when another device adds this device to a new MLS group.
pub async fn upload_mls_key_packages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<Uuid>,
    Json(req): Json<UploadMlsKeyPackagesRequest>,
) -> Result<StatusCode, AppError> {
    verify_device_ownership(&state, auth.user_id, device_id).await?;

    let count = req.key_packages.len();
    if count < MIN_KEY_PACKAGES_PER_UPLOAD || count > MAX_KEY_PACKAGES_PER_UPLOAD {
        return Err(AppError::BadRequest(format!(
            "key_packages count must be between {MIN_KEY_PACKAGES_PER_UPLOAD} and \
             {MAX_KEY_PACKAGES_PER_UPLOAD}; got {count}"
        )));
    }

    for (i, kp) in req.key_packages.iter().enumerate() {
        validate_mls_blob(kp, MAX_KEY_PACKAGE_B64_BYTES).map_err(|_| {
            AppError::BadRequest(format!(
                "key_packages[{i}]: invalid or oversized KeyPackage"
            ))
        })?;
    }

    let mut tx = state.db.begin().await?;
    for kp in &req.key_packages {
        sqlx::query(
            "INSERT INTO mls_key_packages (device_id, key_package_data)
             VALUES ($1, $2)",
        )
        .bind(device_id)
        .bind(kp)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    tracing::info!(
        device_id = %device_id,
        count = count,
        "uploaded MLS KeyPackages"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /users/{username}/mls-key-packages/claim`
///
/// Atomically claim one unclaimed KeyPackage per device for the target user.
/// Each claimed KP is marked as consumed and must not be reused.
/// Used before sending a Commit that adds the target user's devices to a group.
pub async fn claim_mls_key_packages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(username): Path<String>,
    // Rate-limit on the same per-user quota as key-bundle fetches.
) -> Result<Json<ClaimMlsKeyPackagesResponse>, AppError> {
    // Rate limit: same quota as X3DH key bundle fetches (prevents KP scraping).
    if state.rate_limiter.check_key(&auth.user_id).is_err() {
        tracing::warn!(
            requester = %auth.user_id,
            target_username = %username,
            "MLS KeyPackage claim rate limit exceeded"
        );
        return Err(AppError::TooManyRequests);
    }

    // Resolve the target user.
    let target_user_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM users WHERE username = $1",
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await?;

    // Return the same empty list whether the user doesn't exist or has no KPs —
    // no existence oracle.
    let Some(target_user_id) = target_user_id else {
        return Ok(Json(ClaimMlsKeyPackagesResponse { claims: vec![] }));
    };

    // Fetch all devices for the target user.
    let device_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM devices WHERE user_id = $1",
    )
    .bind(target_user_id)
    .fetch_all(&state.db)
    .await?;

    let mut claims = Vec::new();
    let mut tx = state.db.begin().await?;

    for device_id in device_ids {
        // Atomically claim one unclaimed KP for this device.
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "UPDATE mls_key_packages
             SET claimed_at = NOW()
             WHERE id = (
                 SELECT id FROM mls_key_packages
                 WHERE device_id = $1 AND claimed_at IS NULL
                 ORDER BY created_at
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, key_package_data",
        )
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some((_kp_id, key_package_data)) = row {
            claims.push(MlsKeyPackageClaim {
                device_id,
                key_package_data,
            });
        }
    }

    tx.commit().await?;

    tracing::info!(
        requester = %auth.user_id,
        target_username = %username,
        claimed_devices = claims.len(),
        "claimed MLS KeyPackages"
    );
    Ok(Json(ClaimMlsKeyPackagesResponse { claims }))
}

// ─── Group initialization ─────────────────────────────────────────────────────

/// `POST /channels/{id}/mls/init`
///
/// Initialize an MLS group for a channel. May be called exactly once per
/// channel. The creator atomically establishes the initial group state,
/// stores the initial Commit, and delivers Welcomes to all non-creator members.
pub async fn init_mls_group(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<InitMlsGroupRequest>,
) -> Result<Json<InitMlsGroupResponse>, AppError> {
    verify_device_ownership(&state, auth.user_id, req.creator_device_id).await?;

    // Auth user must be a member of the server that owns this channel.
    let is_channel_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM server_members sm
             JOIN channels c ON c.server_id = sm.server_id
             WHERE c.id = $1 AND sm.user_id = $2
         )",
    )
    .bind(channel_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await?;

    if !is_channel_member {
        return Err(AppError::NotFound("Channel not found.".into()));
    }

    // Validate sizes.
    if req.initial_member_device_ids.is_empty()
        || req.initial_member_device_ids.len() > MAX_GROUP_MEMBERS
    {
        return Err(AppError::BadRequest(format!(
            "initial_member_device_ids must have 1–{MAX_GROUP_MEMBERS} entries"
        )));
    }
    if !req
        .initial_member_device_ids
        .contains(&req.creator_device_id)
    {
        return Err(AppError::BadRequest(
            "creator_device_id must be in initial_member_device_ids".into(),
        ));
    }
    validate_mls_blob(&req.initial_commit, MAX_MLS_MESSAGE_B64_BYTES).map_err(|_| {
        AppError::BadRequest("initial_commit: invalid or oversized Commit message".into())
    })?;
    if req.welcome_messages.len() > MAX_WELCOMES_PER_COMMIT {
        return Err(AppError::BadRequest(format!(
            "Too many welcome_messages; max is {MAX_WELCOMES_PER_COMMIT}"
        )));
    }
    for (i, w) in req.welcome_messages.iter().enumerate() {
        validate_mls_blob(&w.welcome_data, MAX_WELCOME_B64_BYTES).map_err(|_| {
            AppError::BadRequest(format!(
                "welcome_messages[{i}]: invalid or oversized Welcome"
            ))
        })?;
    }

    // Validate that all initial members are registered devices belonging to
    // server members. Collect the full set of valid device IDs for this channel.
    let valid_device_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT d.id FROM devices d
         JOIN server_members sm ON sm.user_id = d.user_id
         JOIN channels c ON c.server_id = sm.server_id
         WHERE c.id = $1",
    )
    .bind(channel_id)
    .fetch_all(&state.db)
    .await?;

    let valid_set: std::collections::HashSet<Uuid> =
        valid_device_ids.into_iter().collect();
    for device_id in &req.initial_member_device_ids {
        if !valid_set.contains(device_id) {
            return Err(AppError::BadRequest(format!(
                "Device {device_id} is not a member of this channel's server"
            )));
        }
    }

    let mut tx = state.db.begin().await?;

    // Check for existing group (idempotency on channel_id UNIQUE constraint).
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM mls_groups WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((existing_id,)) = existing {
        // Idempotent: if the same batch_id already initialized this group,
        // return the original response rather than 409.
        let already_has_commit: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM mls_messages
                 WHERE group_id = $1 AND batch_id = $2
             )",
        )
        .bind(existing_id)
        .bind(req.batch_id)
        .fetch_one(&mut *tx)
        .await?;

        if already_has_commit {
            return Ok(Json(InitMlsGroupResponse {
                group_id: existing_id,
                channel_id,
            }));
        }
        return Err(AppError::Conflict(
            "An MLS group already exists for this channel.".into(),
        ));
    }

    // Insert the group.
    let group_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mls_groups (channel_id, group_id_b64, creator_device_id)
         VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(channel_id)
    .bind(&req.group_id_b64)
    .bind(req.creator_device_id)
    .fetch_one(&mut *tx)
    .await?;

    // Insert initial members.
    for device_id in &req.initial_member_device_ids {
        sqlx::query(
            "INSERT INTO mls_group_members (group_id, device_id, added_epoch)
             VALUES ($1, $2, 0)",
        )
        .bind(group_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    }

    // Store initial commit.
    let msg_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO mls_messages (id, batch_id, group_id, sender_device_id,
                                   message_type, epoch, message_data)
         VALUES ($1, $2, $3, $4, 'commit', 0, $5)",
    )
    .bind(msg_id)
    .bind(req.batch_id)
    .bind(group_id)
    .bind(req.creator_device_id)
    .bind(&req.initial_commit)
    .execute(&mut *tx)
    .await?;

    // Store Welcome messages.
    for w in &req.welcome_messages {
        sqlx::query(
            "INSERT INTO mls_welcome_messages
                 (group_id, commit_batch_id, recipient_device_id, welcome_data, epoch)
             VALUES ($1, $2, $3, $4, 0)",
        )
        .bind(group_id)
        .bind(req.batch_id)
        .bind(w.recipient_device_id)
        .bind(&w.welcome_data)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    tracing::info!(
        group_id = %group_id,
        channel_id = %channel_id,
        creator = %req.creator_device_id,
        members = req.initial_member_device_ids.len(),
        "MLS group initialized"
    );
    Ok(Json(InitMlsGroupResponse {
        group_id,
        channel_id,
    }))
}

// ─── Group info ───────────────────────────────────────────────────────────────

/// `GET /channels/{id}/mls/info`
///
/// Returns the current MLS group state for a channel: epoch, member list, etc.
pub async fn get_mls_group_info(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<MlsGroupInfo>, AppError> {
    // Membership check — same oracle-prevention pattern used elsewhere.
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM server_members sm
             JOIN channels c ON c.server_id = sm.server_id
             WHERE c.id = $1 AND sm.user_id = $2
         )",
    )
    .bind(channel_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await?;

    if !is_member {
        return Err(AppError::NotFound("Channel not found.".into()));
    }

    #[derive(sqlx::FromRow)]
    struct GroupRow {
        id: Uuid,
        group_id_b64: String,
        current_epoch: i64,
        created_at: chrono::DateTime<Utc>,
        updated_at: chrono::DateTime<Utc>,
    }

    let group: GroupRow = sqlx::query_as(
        "SELECT id, group_id_b64, current_epoch, created_at, updated_at
         FROM mls_groups WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("No MLS group initialized for this channel.".into()))?;

    let member_device_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT device_id FROM mls_group_members WHERE group_id = $1",
    )
    .bind(group.id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(MlsGroupInfo {
        group_id: group.id,
        channel_id,
        mls_group_id_b64: group.group_id_b64,
        current_epoch: group.current_epoch,
        member_device_ids,
        created_at: group.created_at,
        updated_at: group.updated_at,
    }))
}

// ─── Commit submission ────────────────────────────────────────────────────────

/// `POST /channels/{id}/mls/commit`
///
/// Submit a Commit to advance the MLS group epoch. Enforces:
/// - Epoch monotonicity (commit.epoch == current_epoch).
/// - Single winner per epoch via row-level locking.
/// - Atomic member-list replacement and Welcome delivery.
pub async fn submit_mls_commit(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<SubmitMlsCommitRequest>,
) -> Result<Json<SubmitMlsCommitResponse>, AppError> {
    verify_device_ownership(&state, auth.user_id, req.sender_device_id).await?;

    // Input validation before acquiring locks.
    if req.epoch < 0 {
        return Err(AppError::BadRequest("epoch must be >= 0".into()));
    }
    if req.new_member_device_ids.is_empty()
        || req.new_member_device_ids.len() > MAX_GROUP_MEMBERS
    {
        return Err(AppError::BadRequest(format!(
            "new_member_device_ids must have 1–{MAX_GROUP_MEMBERS} entries"
        )));
    }
    if req.welcome_messages.len() > MAX_WELCOMES_PER_COMMIT {
        return Err(AppError::BadRequest(format!(
            "Too many welcome_messages; max is {MAX_WELCOMES_PER_COMMIT}"
        )));
    }
    validate_mls_blob(&req.commit_data, MAX_MLS_MESSAGE_B64_BYTES).map_err(|_| {
        AppError::BadRequest("commit_data: invalid or oversized Commit message".into())
    })?;
    for (i, w) in req.welcome_messages.iter().enumerate() {
        validate_mls_blob(&w.welcome_data, MAX_WELCOME_B64_BYTES).map_err(|_| {
            AppError::BadRequest(format!(
                "welcome_messages[{i}]: invalid or oversized Welcome"
            ))
        })?;
    }

    let mut tx = state.db.begin().await?;

    // Lock the group row to serialize concurrent Commits for the same epoch.
    #[derive(sqlx::FromRow)]
    struct GroupLock {
        id: Uuid,
        current_epoch: i64,
    }
    let group: GroupLock = sqlx::query_as(
        "SELECT id, current_epoch FROM mls_groups
         WHERE channel_id = $1
         FOR UPDATE",
    )
    .bind(channel_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("No MLS group initialized for this channel.".into()))?;

    // Verify sender is a current group member.
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM mls_group_members
             WHERE group_id = $1 AND device_id = $2
         )",
    )
    .bind(group.id)
    .bind(req.sender_device_id)
    .fetch_one(&mut *tx)
    .await?;

    if !is_member {
        return Err(AppError::Forbidden);
    }

    // Idempotency: if this batch_id was already committed, return the result.
    let existing_epoch: Option<i64> = sqlx::query_scalar(
        "SELECT epoch FROM mls_messages
         WHERE group_id = $1 AND batch_id = $2 AND message_type = 'commit'",
    )
    .bind(group.id)
    .bind(req.batch_id)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(committed_epoch) = existing_epoch {
        return Ok(Json(SubmitMlsCommitResponse {
            new_epoch: committed_epoch + 1,
        }));
    }

    // Epoch check — must match the current group epoch.
    if req.epoch != group.current_epoch {
        return Err(AppError::Conflict(format!(
            "Stale Commit: expected epoch {}, got {}",
            group.current_epoch, req.epoch
        )));
    }

    // Validate all proposed new members are registered server-channel members.
    let valid_device_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT d.id FROM devices d
         JOIN server_members sm ON sm.user_id = d.user_id
         JOIN channels c ON c.server_id = sm.server_id
         WHERE c.id = $1",
    )
    .bind(channel_id)
    .fetch_all(&mut *tx)
    .await?;

    let valid_set: std::collections::HashSet<Uuid> =
        valid_device_ids.into_iter().collect();
    for device_id in &req.new_member_device_ids {
        if !valid_set.contains(device_id) {
            return Err(AppError::BadRequest(format!(
                "Device {device_id} is not a member of this channel's server"
            )));
        }
    }

    let new_epoch = req.epoch + 1;

    // Store Commit message.
    let msg_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO mls_messages (id, batch_id, group_id, sender_device_id,
                                   message_type, epoch, message_data)
         VALUES ($1, $2, $3, $4, 'commit', $5, $6)",
    )
    .bind(msg_id)
    .bind(req.batch_id)
    .bind(group.id)
    .bind(req.sender_device_id)
    .bind(req.epoch)
    .bind(&req.commit_data)
    .execute(&mut *tx)
    .await?;

    // Replace member list atomically.
    sqlx::query("DELETE FROM mls_group_members WHERE group_id = $1")
        .bind(group.id)
        .execute(&mut *tx)
        .await?;

    for device_id in &req.new_member_device_ids {
        sqlx::query(
            "INSERT INTO mls_group_members (group_id, device_id, added_epoch)
             VALUES ($1, $2, $3)",
        )
        .bind(group.id)
        .bind(device_id)
        .bind(new_epoch)
        .execute(&mut *tx)
        .await?;
    }

    // Store Welcome messages.
    for w in &req.welcome_messages {
        sqlx::query(
            "INSERT INTO mls_welcome_messages
                 (group_id, commit_batch_id, recipient_device_id, welcome_data, epoch)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(group.id)
        .bind(req.batch_id)
        .bind(w.recipient_device_id)
        .bind(&w.welcome_data)
        .bind(new_epoch)
        .execute(&mut *tx)
        .await?;
    }

    // Advance the epoch.
    sqlx::query(
        "UPDATE mls_groups
         SET current_epoch = $1, updated_at = NOW()
         WHERE id = $2",
    )
    .bind(new_epoch)
    .bind(group.id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(
        group_id = %group.id,
        channel_id = %channel_id,
        sender = %req.sender_device_id,
        old_epoch = req.epoch,
        new_epoch = new_epoch,
        new_members = req.new_member_device_ids.len(),
        welcomes = req.welcome_messages.len(),
        "MLS Commit accepted"
    );
    Ok(Json(SubmitMlsCommitResponse { new_epoch }))
}

// ─── Application messages ─────────────────────────────────────────────────────

/// `POST /channels/{id}/mls/messages`
///
/// Send a single MLS application-message ciphertext to the group.
/// Stored once; all current members fetch it and decrypt locally.
pub async fn send_mls_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
    Json(req): Json<SendMlsMessageRequest>,
) -> Result<StatusCode, AppError> {
    verify_device_ownership(&state, auth.user_id, req.sender_device_id).await?;

    validate_mls_blob(&req.message_data, MAX_MLS_MESSAGE_B64_BYTES).map_err(|_| {
        AppError::BadRequest("message_data: invalid or oversized application message".into())
    })?;
    if req.epoch < 0 {
        return Err(AppError::BadRequest("epoch must be >= 0".into()));
    }

    // Resolve group and verify membership.
    #[derive(sqlx::FromRow)]
    struct GroupInfo {
        id: Uuid,
        current_epoch: i64,
    }
    let group: GroupInfo = sqlx::query_as(
        "SELECT id, current_epoch FROM mls_groups WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("No MLS group initialized for this channel.".into()))?;

    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM mls_group_members
             WHERE group_id = $1 AND device_id = $2
         )",
    )
    .bind(group.id)
    .bind(req.sender_device_id)
    .fetch_one(&state.db)
    .await?;

    if !is_member {
        return Err(AppError::Forbidden);
    }

    // Accept messages from current or previous epoch to tolerate in-flight
    // messages during an epoch transition. Reject clearly stale epochs.
    if req.epoch < group.current_epoch.saturating_sub(1) {
        return Err(AppError::BadRequest(format!(
            "Message epoch {} is too old; current group epoch is {}",
            req.epoch, group.current_epoch
        )));
    }

    let msg_id = Uuid::now_v7();
    let result = sqlx::query(
        "INSERT INTO mls_messages (id, batch_id, group_id, sender_device_id,
                                   message_type, epoch, message_data)
         VALUES ($1, $2, $3, $4, 'application', $5, $6)
         ON CONFLICT (batch_id, group_id) DO NOTHING",
    )
    .bind(msg_id)
    .bind(req.batch_id)
    .bind(group.id)
    .bind(req.sender_device_id)
    .bind(req.epoch)
    .bind(&req.message_data)
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        // Idempotent retry: already stored.
        return Ok(StatusCode::NO_CONTENT);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /channels/{id}/mls/messages`
///
/// Fetch MLS messages (application + commits) for a group, in order of
/// arrival. Only delivered to devices that are current group members.
pub async fn fetch_mls_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<Uuid>,
    Query(params): Query<FetchMlsMessagesQuery>,
) -> Result<Json<FetchMlsMessagesResponse>, AppError> {
    verify_device_ownership(&state, auth.user_id, params.device_id).await?;

    let limit = params
        .limit
        .unwrap_or(DEFAULT_MESSAGE_PAGE)
        .clamp(1, MAX_MESSAGE_PAGE);

    let group: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM mls_groups WHERE channel_id = $1")
            .bind(channel_id)
            .fetch_optional(&state.db)
            .await?;

    let Some((group_id,)) = group else {
        return Ok(Json(FetchMlsMessagesResponse {
            messages: vec![],
            has_more: false,
        }));
    };

    // Verify the requesting device is a current group member.
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM mls_group_members
             WHERE group_id = $1 AND device_id = $2
         )",
    )
    .bind(group_id)
    .bind(params.device_id)
    .fetch_one(&state.db)
    .await?;

    if !is_member {
        return Err(AppError::Forbidden);
    }

    // Fetch one extra row to determine `has_more` without a second COUNT query.
    #[derive(sqlx::FromRow)]
    struct MsgRow {
        id: Uuid,
        sender_device_id: Uuid,
        message_type: String,
        epoch: i64,
        message_data: String,
        created_at: chrono::DateTime<Utc>,
    }

    let after = params.after.unwrap_or(Uuid::nil());
    let rows: Vec<MsgRow> = sqlx::query_as(
        "SELECT id, sender_device_id, message_type, epoch, message_data, created_at
         FROM mls_messages
         WHERE group_id = $1 AND id > $2
         ORDER BY id
         LIMIT $3",
    )
    .bind(group_id)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let messages: Vec<MlsInboundMessage> = rows
        .into_iter()
        .take(limit as usize)
        .map(|r| MlsInboundMessage {
            id: r.id,
            sender_device_id: r.sender_device_id,
            message_type: r.message_type,
            epoch: r.epoch,
            message_data: r.message_data,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(FetchMlsMessagesResponse { messages, has_more }))
}

// ─── Welcome messages ─────────────────────────────────────────────────────────

/// `GET /devices/{device_id}/mls/welcomes`
///
/// Fetch all pending (undelivered) MLS Welcome messages for this device.
/// Welcomes are marked as delivered after this call so they are not re-sent.
pub async fn fetch_mls_welcomes(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<Uuid>,
) -> Result<Json<FetchMlsWelcomesResponse>, AppError> {
    verify_device_ownership(&state, auth.user_id, device_id).await?;

    #[derive(sqlx::FromRow)]
    struct WelcomeRow {
        id: Uuid,
        group_id: Uuid,
        channel_id: Uuid,
        epoch: i64,
        welcome_data: String,
        created_at: chrono::DateTime<Utc>,
    }

    let rows: Vec<WelcomeRow> = sqlx::query_as(
        "SELECT w.id, w.group_id, mg.channel_id, w.epoch, w.welcome_data, w.created_at
         FROM mls_welcome_messages w
         JOIN mls_groups mg ON mg.id = w.group_id
         WHERE w.recipient_device_id = $1 AND w.delivered_at IS NULL
         ORDER BY w.created_at",
    )
    .bind(device_id)
    .fetch_all(&state.db)
    .await?;

    if rows.is_empty() {
        return Ok(Json(FetchMlsWelcomesResponse { welcomes: vec![] }));
    }

    // Mark all fetched Welcome messages as delivered.
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    sqlx::query(
        "UPDATE mls_welcome_messages
         SET delivered_at = NOW()
         WHERE id = ANY($1)",
    )
    .bind(&ids as &[Uuid])
    .execute(&state.db)
    .await?;

    let welcomes = rows
        .into_iter()
        .map(|r| MlsPendingWelcome {
            id: r.id,
            group_id: r.group_id,
            channel_id: r.channel_id,
            epoch: r.epoch,
            welcome_data: r.welcome_data,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(FetchMlsWelcomesResponse { welcomes }))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Query params for `fetch_mls_messages`.
#[derive(Debug, Deserialize)]
pub struct FetchMlsMessagesQuery {
    pub device_id: Uuid,
    /// Pagination cursor: ID of the last message seen. Omit to start from
    /// the beginning.
    pub after: Option<Uuid>,
    pub limit: Option<i64>,
}

/// Verify that `device_id` is owned by `user_id`. Returns `403 Forbidden`
/// (not `404`) to avoid leaking device-existence information.
async fn verify_device_ownership(
    state: &AppState,
    user_id: Uuid,
    device_id: Uuid,
) -> Result<(), AppError> {
    let owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND user_id = $2)",
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;

    if !owned {
        return Err(AppError::Forbidden);
    }
    Ok(())
}
