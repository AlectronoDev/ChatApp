/**
 * Fetch-based API client.  All requests are proxied through Vite to
 * http://localhost:3000 during development (see vite.config.ts).
 */
const BASE = '/api';
async function request(path, options = {}) {
    const { token, ...init } = options;
    const headers = {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
    const res = await fetch(`${BASE}${path}`, { ...init, headers });
    const text = await res.text();
    if (res.ok) {
        // Some routes return 204 No Content.
        return text ? JSON.parse(text) : {};
    }
    const msg = text
        ? JSON.parse(text).message ?? text
        : res.statusText;
    throw new Error(msg);
}
// ─── Auth ─────────────────────────────────────────────────────────────────────
export const signup = (body) => request('/auth/signup', { method: 'POST', body: JSON.stringify(body) });
export const login = (body) => request('/auth/login', { method: 'POST', body: JSON.stringify(body) });
export const logout = (token) => request('/auth/logout', { method: 'POST', token });
// ─── Devices ──────────────────────────────────────────────────────────────────
export const registerDevice = (token, body) => request('/devices', { method: 'POST', token, body: JSON.stringify(body) });
export const getDevicePublicInfo = (token, deviceId) => request(`/devices/${deviceId}/info`, { token });
export const getUserKeyBundles = (token, username) => request(`/users/${username}/keys`, { token });
// ─── Users ────────────────────────────────────────────────────────────────────
export const getUser = (token, username) => request(`/users/${username}`, { token });
export const searchUsers = (token, q) => request(`/users/search?q=${encodeURIComponent(q)}`, { token });
// ─── DMs ──────────────────────────────────────────────────────────────────────
export const listDms = (token) => request('/dms', { token });
export const createOrGetDm = (token, body) => request('/dms', { method: 'POST', token, body: JSON.stringify(body) });
// ─── DM messages ──────────────────────────────────────────────────────────────
export const sendDmMessage = (token, threadId, body) => request(`/dms/${threadId}/messages`, {
    method: 'POST', token, body: JSON.stringify(body),
});
export const fetchDmMessages = (token, threadId, deviceId, after) => {
    const params = new URLSearchParams({ device_id: deviceId });
    if (after)
        params.set('after', after);
    return request(`/dms/${threadId}/messages?${params}`, { token });
};
export const ackDmMessages = (token, threadId, body) => request(`/dms/${threadId}/messages/ack`, {
    method: 'POST', token, body: JSON.stringify(body),
});
// ─── Servers ──────────────────────────────────────────────────────────────────
export const createServer = (token, body) => request('/servers', { method: 'POST', token, body: JSON.stringify(body) });
export const listServers = (token) => request('/servers', { token });
export const getServer = (token, serverId) => request(`/servers/${serverId}`, { token });
export const inviteToServer = (token, serverId, body) => request(`/servers/${serverId}/invites`, {
    method: 'POST', token, body: JSON.stringify(body),
});
export const leaveServer = (token, serverId, userId) => request(`/servers/${serverId}/members/${userId}`, { method: 'DELETE', token });
export const deleteServer = (token, serverId) => request(`/servers/${serverId}`, { method: 'DELETE', token });
// ─── Channels ─────────────────────────────────────────────────────────────────
export const createChannel = (token, serverId, body) => request(`/servers/${serverId}/channels`, {
    method: 'POST', token, body: JSON.stringify(body),
});
export const listChannels = (token, serverId) => request(`/servers/${serverId}/channels`, { token });
// ─── Channel messages ─────────────────────────────────────────────────────────
export const sendChannelMessage = (token, channelId, body) => request(`/channels/${channelId}/messages`, {
    method: 'POST', token, body: JSON.stringify(body),
});
export const fetchChannelMessages = (token, channelId, deviceId, after) => {
    const params = new URLSearchParams({ device_id: deviceId });
    if (after)
        params.set('after', after);
    return request(`/channels/${channelId}/messages?${params}`, { token });
};
export const ackChannelMessages = (token, channelId, body) => request(`/channels/${channelId}/messages/ack`, {
    method: 'POST', token, body: JSON.stringify(body),
});
// ─── Convenience: resolve a username to (userId, deviceId, dhPubB64) ─────────
export async function resolveUserDevice(token, username) {
    const [bundles, user] = await Promise.all([
        getUserKeyBundles(token, username),
        getUser(token, username),
    ]);
    const first = bundles[0];
    if (!first)
        throw new Error(`${username} has no registered devices`);
    return { userId: user.user_id, deviceId: first.device_id, dhPublicB64: first.identity_dh_key };
}
// ─── Helper: build envelopes for a list of recipients + self-envelope ─────────
import { encryptForDevice, dhPublicKeyB64 } from './crypto';
export function buildEnvelopes(ourDhSecretB64, ourDeviceId, plaintext, aad, recipients) {
    const envelopes = recipients.map(r => ({
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
