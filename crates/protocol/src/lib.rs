//! Shared request/response/event schema types used by both the server and clients.
//!
//! All API contracts live here so the API service and future client code stay
//! in sync through a single source of truth rather than duplicated structs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Utility ──────────────────────────────────────────────────────────────────

/// Returned by every failed API call so clients have a consistent error shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Machine-readable error code (e.g. "INVALID_CREDENTIALS").
    pub code: String,
    /// Human-readable description.
    pub message: String,
}

// ─── Health ───────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub password: String,
}

/// Returned once at signup. `recovery_code` is shown exactly once and never
/// stored in plaintext on the server — the client must save it securely.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignupResponse {
    pub user_id: Uuid,
    pub username: String,
    /// One-time recovery code. Store this somewhere safe.
    pub recovery_code: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub user_id: Uuid,
    pub username: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverRequest {
    pub username: String,
    pub recovery_code: String,
    pub new_password: String,
}

/// Returned after a successful password recovery. A fresh recovery code is
/// generated and shown once — the old one is permanently invalidated.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoverResponse {
    pub new_recovery_code: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: Uuid,
    pub username: String,
}

// ─── Users ────────────────────────────────────────────────────────────────────

/// Returned by user lookup and search endpoints. Contains only public
/// information — no credentials, no private key material.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserSearchResult {
    pub user_id: Uuid,
    pub username: String,
}

// ─── Direct messages ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDmRequest {
    pub with_user_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDmResponse {
    pub thread_id: Uuid,
    /// `true` if this call created a new thread, `false` if one already existed.
    pub created: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DmThreadSummary {
    pub thread_id: Uuid,
    pub other_user: UserSearchResult,
    pub created_at: DateTime<Utc>,
}

// ─── Messages ─────────────────────────────────────────────────────────────────

/// One per-device ciphertext envelope within a single logical message send.
#[derive(Debug, Serialize, Deserialize)]
pub struct OutboundEnvelope {
    pub recipient_device_id: Uuid,
    /// base64-encoded ciphertext produced by the client's Double Ratchet session.
    pub ciphertext: String,
}

/// A client sends one logical message as a batch of per-device envelopes.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// The sender's own device ID — validated server-side to belong to the
    /// authenticated user.
    pub sender_device_id: Uuid,
    pub envelopes: Vec<OutboundEnvelope>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageResponse {
    /// UUID v7 identifying this logical message. Use as a pagination cursor.
    pub batch_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// One logical message as seen by a specific recipient device.
#[derive(Debug, Serialize, Deserialize)]
pub struct InboundMessage {
    /// Logical message identifier (same across all per-device envelopes).
    pub batch_id: Uuid,
    pub sender_user_id: Uuid,
    pub sender_device_id: Uuid,
    /// base64-encoded ciphertext for this device's Double Ratchet session.
    pub ciphertext: String,
    pub created_at: DateTime<Utc>,
    /// Set when this envelope was acknowledged by the recipient device.
    pub delivered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchMessagesResponse {
    pub messages: Vec<InboundMessage>,
    /// `true` if there are more messages in the requested direction.
    pub has_more: bool,
}

/// Request body for bulk-acknowledging delivered messages.
#[derive(Debug, Serialize, Deserialize)]
pub struct AckMessagesRequest {
    pub device_id: Uuid,
    pub batch_ids: Vec<Uuid>,
}

// ─── Devices ──────────────────────────────────────────────────────────────────

/// A signed prekey: an X25519 public key signed by the device's Ed25519
/// identity key to prove authenticity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekey {
    pub key_id: i32,
    /// base64-encoded X25519 public key.
    pub public_key: String,
    /// base64-encoded Ed25519 signature over `key_id || public_key`.
    pub signature: String,
}

/// A single-use X25519 public key for X3DH session establishment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePrekey {
    pub key_id: i32,
    /// base64-encoded X25519 public key.
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub display_name: String,
    /// base64-encoded Ed25519 public key.
    pub identity_key: String,
    /// base64-encoded X25519 public key.
    pub identity_dh_key: String,
    pub signed_prekey: SignedPrekey,
    /// May be empty but clients should upload a batch (e.g. 20–100 keys).
    pub one_time_prekeys: Vec<OneTimePrekey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    pub device_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub device_id: Uuid,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}

/// Public identity keys for a single device — returned by GET /devices/:id.
/// Does NOT consume any one-time prekeys. Used by recipients to look up a
/// sender's DH public key so they can derive the session key for decryption.
#[derive(Debug, Serialize, Deserialize)]
pub struct DevicePublicInfo {
    pub device_id: Uuid,
    /// base64-encoded Ed25519 public key.
    pub identity_key: String,
    /// base64-encoded X25519 public key.
    pub identity_dh_key: String,
}

/// The full public key bundle for one device returned when a peer wants to
/// initiate an E2EE session. Contains one consumed one-time prekey if available.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceKeyBundle {
    pub device_id: Uuid,
    /// base64-encoded Ed25519 public key.
    pub identity_key: String,
    /// base64-encoded X25519 public key.
    pub identity_dh_key: String,
    pub signed_prekey: SignedPrekey,
    /// Present if a one-time prekey was available and has been consumed.
    pub one_time_prekey: Option<OneTimePrekey>,
}

// ─── Servers ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateServerRequest {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateServerResponse {
    pub server_id: Uuid,
}

/// Compact server entry used in list responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerSummary {
    pub server_id: Uuid,
    pub name: String,
    /// The authenticated user's role in this server: `"owner"` or `"member"`.
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// One member as returned inside `ServerDetails`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerMember {
    pub user_id: Uuid,
    pub username: String,
    /// `"owner"` or `"member"`.
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

/// Full server information including the member list.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerDetails {
    pub server_id: Uuid,
    pub name: String,
    pub members: Vec<ServerMember>,
    pub created_at: DateTime<Utc>,
}

/// Request body for inviting another user into a server.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteToServerRequest {
    /// The user_id of the person to invite.
    pub user_id: Uuid,
}

// ─── Channels ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateChannelRequest {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateChannelResponse {
    pub channel_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChannelSummary {
    pub channel_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

// ─── Channel messages ─────────────────────────────────────────────────────────
//
// Channel messages reuse the same request/response types as DM messages
// (`SendMessageRequest`, `SendMessageResponse`, `InboundMessage`,
// `FetchMessagesResponse`, `AckMessagesRequest`) — no new types needed.

