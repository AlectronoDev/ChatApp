/**
 * TypeScript types mirroring the Rust `crates/protocol` crate.
 * Keep in sync with `crates/protocol/src/lib.rs`.
 */

// ─── Auth ─────────────────────────────────────────────────────────────────────

export interface SignupRequest { username: string; password: string }
export interface SignupResponse {
  user_id: string; username: string; recovery_code: string;
  token: string; expires_at: string;
}
export interface LoginRequest { username: string; password: string }
export interface LoginResponse {
  user_id: string; username: string; token: string; expires_at: string;
}

// ─── Users ────────────────────────────────────────────────────────────────────

export interface UserSearchResult { user_id: string; username: string }

// ─── Devices ──────────────────────────────────────────────────────────────────

export interface SignedPrekey { key_id: number; public_key: string; signature: string }
export interface RegisterDeviceRequest {
  display_name: string; identity_key: string; identity_dh_key: string;
  signed_prekey: SignedPrekey; one_time_prekeys: [];
}
export interface RegisterDeviceResponse { device_id: string }
export interface DevicePublicInfo { device_id: string; identity_key: string; identity_dh_key: string }
export interface DeviceKeyBundle {
  device_id: string; identity_key: string; identity_dh_key: string;
  signed_prekey: SignedPrekey; one_time_prekey: SignedPrekey | null;
}

// ─── DMs ──────────────────────────────────────────────────────────────────────

export interface CreateDmRequest { with_user_id: string }
export interface CreateDmResponse { thread_id: string; created: boolean }
export interface DmThreadSummary {
  thread_id: string; other_user: UserSearchResult; created_at: string;
}

// ─── Messages (shared for DMs and channels) ───────────────────────────────────

export interface OutboundEnvelope { recipient_device_id: string; ciphertext: string }
export interface SendMessageRequest { sender_device_id: string; envelopes: OutboundEnvelope[] }
export interface SendMessageResponse { batch_id: string; created_at: string }
export interface InboundMessage {
  batch_id: string; sender_user_id: string; sender_device_id: string;
  ciphertext: string; created_at: string; delivered_at: string | null;
}
export interface FetchMessagesResponse { messages: InboundMessage[]; has_more: boolean }
export interface AckMessagesRequest { device_id: string; batch_ids: string[] }

// ─── Servers ──────────────────────────────────────────────────────────────────

export interface CreateServerRequest { name: string }
export interface CreateServerResponse { server_id: string }
export interface ServerSummary { server_id: string; name: string; role: string; created_at: string }
export interface ServerMember { user_id: string; username: string; role: string; joined_at: string }
export interface ServerDetails {
  server_id: string; name: string; members: ServerMember[]; created_at: string;
}
export interface InviteToServerRequest { user_id: string }

// ─── Channels ─────────────────────────────────────────────────────────────────

export interface CreateChannelRequest { name: string }
export interface CreateChannelResponse { channel_id: string }
export interface ChannelSummary { channel_id: string; name: string; created_at: string }

// ─── Decrypted message (client-only) ──────────────────────────────────────────

export interface DecryptedMessage {
  batchId: string;
  senderUserId: string;
  senderUsername: string;
  plaintext: string;
  createdAt: Date;
}
