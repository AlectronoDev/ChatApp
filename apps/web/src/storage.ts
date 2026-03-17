/**
 * Persist the client session (auth token + device key material) in localStorage.
 *
 * Keys never leave the browser in plaintext.  On logout the entire entry is
 * wiped so there is no residual key material in storage.
 */

const SESSION_KEY = 'chat_session';

export interface StoredSession {
  username: string;
  userId: string;
  token: string;
  deviceId: string;
  /** base64-encoded 32-byte X25519 DH secret */
  dhSecretB64: string;
  /** device_id (string) → identity_dh_key (base64) */
  peerDhCache: Record<string, string>;
  /** user_id (string) → username */
  peerUsernames: Record<string, string>;
  /** user_id (string) → [device_id, identity_dh_key_b64] */
  userDeviceCache: Record<string, [string, string]>;
}

export function loadSession(): StoredSession | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StoredSession;
  } catch {
    return null;
  }
}

export function saveSession(session: StoredSession): void {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

/**
 * On logout, keep device key material so the user can re-login on the same
 * browser and decrypt their existing messages. Only the auth token is cleared.
 * App.tsx treats an empty token as "not authenticated".
 */
export function clearSession(): void {
  const current = loadSession();
  if (current) {
    saveSession({ ...current, token: '' });
  } else {
    localStorage.removeItem(SESSION_KEY);
  }
}
