/**
 * Persist the client session (auth token + device key material) in localStorage.
 *
 * Keys never leave the browser in plaintext.  On logout the entire entry is
 * wiped so there is no residual key material in storage.
 */
const SESSION_KEY = 'chat_session';
export function loadSession() {
    try {
        const raw = localStorage.getItem(SESSION_KEY);
        if (!raw)
            return null;
        return JSON.parse(raw);
    }
    catch {
        return null;
    }
}
export function saveSession(session) {
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}
/**
 * On logout, keep device key material so the user can re-login on the same
 * browser and decrypt their existing messages. Only the auth token is cleared.
 * App.tsx treats an empty token as "not authenticated".
 */
export function clearSession() {
    const current = loadSession();
    if (current) {
        saveSession({ ...current, token: '' });
    }
    else {
        localStorage.removeItem(SESSION_KEY);
    }
}
