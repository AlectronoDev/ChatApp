/**
 * Fetch-based API client.  All requests are proxied through Vite to
 * http://localhost:3000 during development (see vite.config.ts).
 */

import type {
  AckMessagesRequest, ChannelSummary, CreateChannelRequest, CreateChannelResponse,
  CreateDmRequest, CreateDmResponse, CreateServerRequest, CreateServerResponse,
  DeviceKeyBundle, DevicePublicInfo, DmThreadSummary, FetchMessagesResponse,
  InviteToServerRequest, LoginRequest, LoginResponse,
  OutboundEnvelope, RegisterDeviceRequest, RegisterDeviceResponse,
  SendMessageRequest, SendMessageResponse, ServerDetails, ServerSummary,
  SignupRequest, SignupResponse, UserSearchResult,
} from './types';

const BASE = '/api';

async function request<T>(
  path: string,
  options: RequestInit & { token?: string } = {},
): Promise<T> {
  const { token, ...init } = options;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  const text = await res.text();

  if (res.ok) {
    // Some routes return 204 No Content.
    return text ? (JSON.parse(text) as T) : ({} as T);
  }

  const msg =
    text
      ? (JSON.parse(text) as { message?: string }).message ?? text
      : res.statusText;
  throw new Error(msg);
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const signup = (body: SignupRequest) =>
  request<SignupResponse>('/auth/signup', { method: 'POST', body: JSON.stringify(body) });

export const login = (body: LoginRequest) =>
  request<LoginResponse>('/auth/login', { method: 'POST', body: JSON.stringify(body) });

export const logout = (token: string) =>
  request<void>('/auth/logout', { method: 'POST', token });

// ─── Devices ──────────────────────────────────────────────────────────────────

export const registerDevice = (token: string, body: RegisterDeviceRequest) =>
  request<RegisterDeviceResponse>('/devices', { method: 'POST', token, body: JSON.stringify(body) });

export const getDevicePublicInfo = (token: string, deviceId: string) =>
  request<DevicePublicInfo>(`/devices/${deviceId}/info`, { token });

export const getUserKeyBundles = (token: string, username: string) =>
  request<DeviceKeyBundle[]>(`/users/${username}/keys`, { token });

// ─── Users ────────────────────────────────────────────────────────────────────

export const getUser = (token: string, username: string) =>
  request<UserSearchResult>(`/users/${username}`, { token });

export const searchUsers = (token: string, q: string) =>
  request<UserSearchResult[]>(`/users/search?q=${encodeURIComponent(q)}`, { token });

// ─── DMs ──────────────────────────────────────────────────────────────────────

export const listDms = (token: string) =>
  request<DmThreadSummary[]>('/dms', { token });

export const createOrGetDm = (token: string, body: CreateDmRequest) =>
  request<CreateDmResponse>('/dms', { method: 'POST', token, body: JSON.stringify(body) });

// ─── DM messages ──────────────────────────────────────────────────────────────

export const sendDmMessage = (token: string, threadId: string, body: SendMessageRequest) =>
  request<SendMessageResponse>(`/dms/${threadId}/messages`, {
    method: 'POST', token, body: JSON.stringify(body),
  });

export const fetchDmMessages = (
  token: string, threadId: string, deviceId: string, after?: string,
) => {
  const params = new URLSearchParams({ device_id: deviceId });
  if (after) params.set('after', after);
  return request<FetchMessagesResponse>(`/dms/${threadId}/messages?${params}`, { token });
};

export const ackDmMessages = (token: string, threadId: string, body: AckMessagesRequest) =>
  request<void>(`/dms/${threadId}/messages/ack`, {
    method: 'POST', token, body: JSON.stringify(body),
  });

// ─── Servers ──────────────────────────────────────────────────────────────────

export const createServer = (token: string, body: CreateServerRequest) =>
  request<CreateServerResponse>('/servers', { method: 'POST', token, body: JSON.stringify(body) });

export const listServers = (token: string) =>
  request<ServerSummary[]>('/servers', { token });

export const getServer = (token: string, serverId: string) =>
  request<ServerDetails>(`/servers/${serverId}`, { token });

export const inviteToServer = (token: string, serverId: string, body: InviteToServerRequest) =>
  request<void>(`/servers/${serverId}/invites`, {
    method: 'POST', token, body: JSON.stringify(body),
  });

export const leaveServer = (token: string, serverId: string, userId: string) =>
  request<void>(`/servers/${serverId}/members/${userId}`, { method: 'DELETE', token });

export const deleteServer = (token: string, serverId: string) =>
  request<void>(`/servers/${serverId}`, { method: 'DELETE', token });

// ─── Channels ─────────────────────────────────────────────────────────────────

export const createChannel = (token: string, serverId: string, body: CreateChannelRequest) =>
  request<CreateChannelResponse>(`/servers/${serverId}/channels`, {
    method: 'POST', token, body: JSON.stringify(body),
  });

export const listChannels = (token: string, serverId: string) =>
  request<ChannelSummary[]>(`/servers/${serverId}/channels`, { token });

// ─── Channel messages ─────────────────────────────────────────────────────────

export const sendChannelMessage = (token: string, channelId: string, body: SendMessageRequest) =>
  request<SendMessageResponse>(`/channels/${channelId}/messages`, {
    method: 'POST', token, body: JSON.stringify(body),
  });

export const fetchChannelMessages = (
  token: string, channelId: string, deviceId: string, after?: string,
) => {
  const params = new URLSearchParams({ device_id: deviceId });
  if (after) params.set('after', after);
  return request<FetchMessagesResponse>(`/channels/${channelId}/messages?${params}`, { token });
};

export const ackChannelMessages = (token: string, channelId: string, body: AckMessagesRequest) =>
  request<void>(`/channels/${channelId}/messages/ack`, {
    method: 'POST', token, body: JSON.stringify(body),
  });

// ─── Convenience: resolve a username to (userId, deviceId, dhPubB64) ─────────

export async function resolveUserDevice(
  token: string,
  username: string,
): Promise<{ userId: string; deviceId: string; dhPublicB64: string }> {
  const [bundles, user] = await Promise.all([
    getUserKeyBundles(token, username),
    getUser(token, username),
  ]);
  const first = bundles[0];
  if (!first) throw new Error(`${username} has no registered devices`);
  return { userId: user.user_id, deviceId: first.device_id, dhPublicB64: first.identity_dh_key };
}

// ─── Helper: build envelopes for a list of recipients + self-envelope ─────────

import { encryptForDevice, dhPublicKeyB64 } from './crypto';

export interface Recipient { deviceId: string; dhPublicB64: string }

export function buildEnvelopes(
  ourDhSecretB64: string,
  ourDeviceId: string,
  plaintext: string,
  aad: Uint8Array,
  recipients: Recipient[],
): OutboundEnvelope[] {
  const envelopes: OutboundEnvelope[] = recipients.map(r => ({
    recipient_device_id: r.deviceId,
    ciphertext: encryptForDevice(ourDhSecretB64, r.dhPublicB64, plaintext, aad),
  }));

  // Self-envelope using self-ECDH so the sender can see their own messages.
  const ownPub = dhPublicKeyB64(ourDhSecretB64);
  envelopes.push({
    recipient_device_id: ourDeviceId,
    ciphertext: encryptForDevice(ourDhSecretB64, ownPub, plaintext, aad),
  });

  return envelopes;
}
