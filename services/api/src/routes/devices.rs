use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use crate::{error::AppError, extract::AuthUser, state::AppState};
use protocol::{
    DeviceKeyBundle, DevicePublicInfo, DeviceSummary, OneTimePrekey, RegisterDeviceRequest,
    RegisterDeviceResponse, SignedPrekey,
};

// ─── Register a device ────────────────────────────────────────────────────────

pub async fn register_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<(StatusCode, Json<RegisterDeviceResponse>), AppError> {
    validate_base64_field(&req.identity_key, "identity_key")?;
    validate_base64_field(&req.identity_dh_key, "identity_dh_key")?;
    validate_base64_field(&req.signed_prekey.public_key, "signed_prekey.public_key")?;
    validate_base64_field(&req.signed_prekey.signature, "signed_prekey.signature")?;

    let mut tx = state.db.begin().await?;

    let device_id = sqlx::query_scalar!(
        r#"
        INSERT INTO devices
            (user_id, display_name, identity_key, identity_dh_key,
             signed_prekey_id, signed_prekey_pub, signed_prekey_sig)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
        auth.user_id,
        req.display_name,
        req.identity_key,
        req.identity_dh_key,
        req.signed_prekey.key_id,
        req.signed_prekey.public_key,
        req.signed_prekey.signature,
    )
    .fetch_one(&mut *tx)
    .await?;

    for otpk in &req.one_time_prekeys {
        validate_base64_field(&otpk.public_key, "one_time_prekey.public_key")?;

        sqlx::query!(
            "INSERT INTO device_one_time_prekeys (device_id, key_id, public_key)
             VALUES ($1, $2, $3)",
            device_id,
            otpk.key_id,
            otpk.public_key,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    tracing::info!(
        user_id = %auth.user_id,
        device_id = %device_id,
        prekeys_uploaded = req.one_time_prekeys.len(),
        "device registered"
    );

    Ok((
        StatusCode::CREATED,
        Json(RegisterDeviceResponse { device_id }),
    ))
}

// ─── List own devices ─────────────────────────────────────────────────────────

pub async fn list_devices(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<DeviceSummary>>, AppError> {
    let rows = sqlx::query!(
        "SELECT id, display_name, created_at, last_active_at
         FROM devices WHERE user_id = $1 ORDER BY created_at ASC",
        auth.user_id,
    )
    .fetch_all(&state.db)
    .await?;

    let devices = rows
        .into_iter()
        .map(|r| DeviceSummary {
            device_id: r.id,
            display_name: r.display_name,
            created_at: r.created_at,
            last_active_at: r.last_active_at,
        })
        .collect();

    Ok(Json(devices))
}

// ─── Delete a device ──────────────────────────────────────────────────────────

pub async fn delete_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<uuid::Uuid>,
) -> Result<StatusCode, AppError> {
    let result = sqlx::query!(
        "DELETE FROM devices WHERE id = $1 AND user_id = $2",
        device_id,
        auth.user_id,
    )
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Device not found.".into()));
    }

    tracing::info!(user_id = %auth.user_id, device_id = %device_id, "device removed");

    Ok(StatusCode::NO_CONTENT)
}

// ─── Fetch peer key bundles ───────────────────────────────────────────────────

/// Returns one key bundle per device registered to the target user. Consumes
/// one one-time prekey per device atomically. Used by initiating clients to
/// set up X3DH sessions.
pub async fn get_user_key_bundles(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(username): Path<String>,
) -> Result<Json<Vec<DeviceKeyBundle>>, AppError> {
    let target = sqlx::query!(
        "SELECT id FROM users WHERE username = $1",
        username,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("User '{username}' not found.")))?;

    let devices = sqlx::query!(
        r#"
        SELECT id, identity_key, identity_dh_key,
               signed_prekey_id, signed_prekey_pub, signed_prekey_sig
        FROM devices WHERE user_id = $1
        "#,
        target.id,
    )
    .fetch_all(&state.db)
    .await?;

    let mut bundles = Vec::with_capacity(devices.len());

    for device in devices {
        // Atomically claim one unconsumed one-time prekey for this device.
        let otpk = sqlx::query!(
            r#"
            UPDATE device_one_time_prekeys
            SET consumed_at = NOW()
            WHERE id = (
                SELECT id FROM device_one_time_prekeys
                WHERE device_id = $1 AND consumed_at IS NULL
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING key_id, public_key
            "#,
            device.id,
        )
        .fetch_optional(&state.db)
        .await?
        .map(|r| OneTimePrekey {
            key_id: r.key_id,
            public_key: r.public_key,
        });

        bundles.push(DeviceKeyBundle {
            device_id: device.id,
            identity_key: device.identity_key,
            identity_dh_key: device.identity_dh_key,
            signed_prekey: SignedPrekey {
                key_id: device.signed_prekey_id,
                public_key: device.signed_prekey_pub,
                signature: device.signed_prekey_sig,
            },
            one_time_prekey: otpk,
        });
    }

    Ok(Json(bundles))
}

// ─── Public device info (no prekey consumption) ───────────────────────────────

/// Returns only the identity keys for a device. Does not consume any one-time
/// prekeys. Used by message recipients to look up a sender's DH public key
/// in order to derive the session key for decryption.
pub async fn get_device_public_info(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(device_id): Path<uuid::Uuid>,
) -> Result<Json<DevicePublicInfo>, AppError> {
    let row = sqlx::query!(
        "SELECT id, identity_key, identity_dh_key FROM devices WHERE id = $1",
        device_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Device not found.".into()))?;

    Ok(Json(DevicePublicInfo {
        device_id: row.id,
        identity_key: row.identity_key,
        identity_dh_key: row.identity_dh_key,
    }))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn validate_base64_field(value: &str, field: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(AppError::BadRequest(format!("'{field}' must not be empty.")));
    }
    Ok(())
}
