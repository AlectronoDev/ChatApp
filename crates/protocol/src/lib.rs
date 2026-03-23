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

/// Public key material included with the first Double Ratchet message of a new
/// X3DH session. Absent on all subsequent ratchet messages in the same session.
///
/// The responder uses these fields to reproduce the initiator's DH operations
/// and derive the same shared root secret (`SK`). All byte arrays are
/// base64-encoded (standard alphabet with padding), matching the encoding used
/// by `crates/crypto_core`.
///
/// See `docs/protocol.md` §"X3DH bootstrap message format" for the exact layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X3dhInitData {
    /// base64-encoded 32-byte X25519 identity DH public key of the initiator.
    pub ik_dh_pub: String,
    /// base64-encoded 32-byte X25519 ephemeral public key of the initiator.
    pub ek_pub: String,
    /// `key_id` of the responder's signed prekey that the initiator used.
    pub spk_id: i32,
    /// `key_id` of the responder's one-time prekey used, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otpk_id: Option<i32>,
}

/// One per-device ciphertext envelope within a single logical message send.
#[derive(Debug, Serialize, Deserialize)]
pub struct OutboundEnvelope {
    pub recipient_device_id: Uuid,
    /// Protocol version. Must be `1`. Future incompatible protocol changes
    /// increment this; the server rejects any unrecognized version.
    pub protocol_version: u8,
    /// Complete Double Ratchet message (header + AEAD ciphertext), base64-encoded.
    /// Opaque to the server — it stores and relays this blob without interpretation.
    pub ciphertext: String,
    /// Present only on the very first envelope of a new X3DH session between
    /// this sender device and this recipient device. Absent for all subsequent
    /// ratchet messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x3dh_init: Option<X3dhInitData>,
}

/// A client sends one logical message as a batch of per-device envelopes.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// The sender's own device ID — validated server-side to belong to the
    /// authenticated user.
    pub sender_device_id: Uuid,
    /// Client-generated UUID v7 used as an idempotency key. If the server has
    /// already accepted a batch with this ID from the same sender in the same
    /// thread, it returns the original response without inserting duplicates.
    /// Clients must generate a fresh UUID v7 for each new logical message and
    /// reuse it on every retry of the same message.
    pub batch_id: Uuid,
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
    /// Protocol version as stored when the message was sent.
    pub protocol_version: u8,
    /// Complete Double Ratchet message for this device's session, base64-encoded.
    pub ciphertext: String,
    /// Present if this envelope initiated a new X3DH session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x3dh_init: Option<X3dhInitData>,
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
    /// base64-encoded Ed25519 signature over `key_id_be32 ‖ public_key_bytes`
    /// (4-byte big-endian key ID concatenated with the 32-byte X25519 public key).
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
    /// At least 10 keys are required at registration; uploading 50–100 is
    /// recommended so fresh key material is available for many concurrent
    /// session initiations before the device needs to replenish.
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

// ─── User profiles ────────────────────────────────────────────────────────────

/// Public profile returned by `GET /users/{username}/profile`.
/// All optional fields are absent when the user has not set them.
#[derive(Debug, Serialize, Deserialize)]
pub struct PublicProfile {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
}

/// Request body for `PATCH /users/me/profile`.
/// All fields are optional — only the fields present in the request are written.
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
}

/// Request body for `DELETE /users/me`.
/// Password confirmation is required before account deletion.
#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub password: String,
}

// ─── Ratchet session state storage ───────────────────────────────────────────

/// Request body for creating or updating an encrypted ratchet session state
/// record on the server.
///
/// The client encrypts the serialized `RatchetSession` with a key that never
/// leaves the device before uploading. The server stores and returns this blob
/// verbatim and cannot read or validate its contents.
#[derive(Debug, Serialize, Deserialize)]
pub struct PutRatchetSessionRequest {
    /// The version number the client last read from the server for this session.
    /// For the initial creation of a session record, use `0`.
    /// The server rejects the request with 409 Conflict if the stored version
    /// no longer matches — indicating a concurrent update from another client
    /// instance. The client must re-read the current state and retry.
    pub expected_version: i64,
    /// Client-side encrypted session state blob, base64-encoded.
    /// Maximum size: 64 KiB.
    pub encrypted_state: String,
}

/// Returned by `GET` and `PUT` ratchet-session endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct RatchetSessionResponse {
    /// Monotonically increasing version number. Incremented by 1 on every
    /// successful PUT. Use this as `expected_version` in the next PUT.
    pub version: i64,
    /// The encrypted state blob. Present on GET responses; absent on PUT
    /// responses (the client already has the new state it just uploaded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_state: Option<String>,
    pub updated_at: DateTime<Utc>,
}

// ─── Channel messages ─────────────────────────────────────────────────────────
//
// Channel messages reuse the same request/response types as DM messages
// (`SendMessageRequest`, `SendMessageResponse`, `InboundMessage`,
// `FetchMessagesResponse`, `AckMessagesRequest`) — no new types needed.

// ─── MLS: KeyPackage management ───────────────────────────────────────────────

/// Upload one or more MLS KeyPackages for this device.
///
/// KeyPackages are consumed one-at-a-time when another device adds this device
/// to a new MLS group (analogous to one-time prekeys in X3DH). Each entry in
/// `key_packages` is a base64-encoded TLS-encoded KeyPackage per RFC 9420 §10.
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadMlsKeyPackagesRequest {
    pub key_packages: Vec<String>,
}

/// A claimed KeyPackage returned when listing key material for a target user.
/// The claimant uses this to build a `Welcome` message addressed to `device_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsKeyPackageClaim {
    pub device_id: Uuid,
    /// base64-encoded TLS-encoded KeyPackage (opaque to the server).
    pub key_package_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimMlsKeyPackagesResponse {
    /// One entry per device belonging to the target user that has an available
    /// KeyPackage. Devices with no remaining KeyPackages are omitted.
    pub claims: Vec<MlsKeyPackageClaim>,
}

// ─── MLS: Group initialization ────────────────────────────────────────────────

/// Per-device Welcome envelope included in a Commit that adds new members.
/// Each Welcome is encrypted to the recipient's KeyPackage HPKE init key;
/// no one other than the recipient (and whoever holds the matching private key)
/// can read the group secrets it carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsWelcomeEnvelope {
    pub recipient_device_id: Uuid,
    /// base64-encoded TLS-encoded MLS Welcome message per RFC 9420 §12.4.3.1.
    pub welcome_data: String,
}

/// Initialize an MLS group for a channel.
///
/// May be called exactly once per channel. The creator establishes the initial
/// group state and, if adding others in the same operation, provides Welcome
/// messages for each initial non-creator member.
#[derive(Debug, Serialize, Deserialize)]
pub struct InitMlsGroupRequest {
    pub creator_device_id: Uuid,
    /// Opaque MLS group_id chosen by the creator, base64-encoded bytes.
    /// This is NOT the channel UUID — it is the raw MLS GroupID value.
    pub group_id_b64: String,
    /// Complete initial member set (device IDs). Must include `creator_device_id`.
    pub initial_member_device_ids: Vec<Uuid>,
    /// Client-provided UUID v7 for idempotency. Resubmitting the same
    /// `batch_id` for the same channel returns the original response.
    pub batch_id: Uuid,
    /// base64-encoded TLS-encoded initial Commit message.
    pub initial_commit: String,
    /// Welcome messages for all initial members other than the creator.
    pub welcome_messages: Vec<MlsWelcomeEnvelope>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitMlsGroupResponse {
    /// Server-assigned UUID for this MLS group (used in subsequent API calls).
    pub group_id: Uuid,
    pub channel_id: Uuid,
}

// ─── MLS: Commits (membership changes and key updates) ────────────────────────

/// Submit a Commit message to advance the MLS group epoch.
///
/// Commits are the only mechanism for group state changes: member add/remove,
/// ratchet-tree key rotation (Update), and external Commits. The server
/// enforces that `epoch == current_epoch` to reject stale or replayed Commits.
/// The first Commit for a given epoch wins; concurrent duplicates receive 409.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitMlsCommitRequest {
    pub sender_device_id: Uuid,
    /// Client-provided UUID v7 for idempotency.
    pub batch_id: Uuid,
    /// The epoch this Commit was created in.  Must equal the group's
    /// `current_epoch`. Acceptance advances the group to `epoch + 1`.
    pub epoch: i64,
    /// base64-encoded TLS-encoded MLSMessage containing the Commit.
    pub commit_data: String,
    /// Complete member set AFTER this Commit takes effect.
    /// The server replaces the stored member list atomically.
    /// All IDs must be valid, registered devices that are server members.
    pub new_member_device_ids: Vec<Uuid>,
    /// Welcome messages for any devices newly added by this Commit.
    pub welcome_messages: Vec<MlsWelcomeEnvelope>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitMlsCommitResponse {
    /// The new epoch number after the Commit was accepted.
    pub new_epoch: i64,
}

// ─── MLS: Application messages ───────────────────────────────────────────────

/// Send an MLS application message to the group.
///
/// Unlike legacy per-device channel envelopes, an MLS application message is
/// a SINGLE group ciphertext decryptable by all current members using the
/// epoch encryption key. The server fans it out to all current members.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendMlsMessageRequest {
    pub sender_device_id: Uuid,
    /// Client-provided UUID v7 for idempotency.
    pub batch_id: Uuid,
    /// The epoch this message was encrypted in.
    pub epoch: i64,
    /// base64-encoded TLS-encoded MLSMessage (PrivateMessage, application type).
    pub message_data: String,
}

/// A single MLS message as returned in a fetch response.
#[derive(Debug, Serialize, Deserialize)]
pub struct MlsInboundMessage {
    /// Server-assigned UUID v7; use as `after` cursor in the next fetch.
    pub id: Uuid,
    pub sender_device_id: Uuid,
    /// "application" or "commit".
    pub message_type: String,
    pub epoch: i64,
    pub message_data: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchMlsMessagesResponse {
    pub messages: Vec<MlsInboundMessage>,
    /// `true` if more messages exist beyond this page.
    pub has_more: bool,
}

// ─── MLS: Welcome messages for new members ────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsPendingWelcome {
    /// Row ID — use for ACK.
    pub id: Uuid,
    /// Server-side MLS group UUID.
    pub group_id: Uuid,
    pub channel_id: Uuid,
    pub epoch: i64,
    /// base64-encoded TLS-encoded Welcome (opaque; encrypted to this device).
    pub welcome_data: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchMlsWelcomesResponse {
    pub welcomes: Vec<MlsPendingWelcome>,
}

// ─── MLS: Group info ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct MlsGroupInfo {
    /// Server-assigned UUID for this group.
    pub group_id: Uuid,
    pub channel_id: Uuid,
    /// Opaque MLS GroupID chosen by the creator (base64-encoded bytes).
    pub mls_group_id_b64: String,
    pub current_epoch: i64,
    pub member_device_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

