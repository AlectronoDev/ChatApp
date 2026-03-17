import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { loadSession, saveSession, clearSession, type StoredSession } from '../storage';

// ─── State ────────────────────────────────────────────────────────────────────

export interface SessionState {
  isLoaded: boolean;
  session: StoredSession | null;
}

// ─── Actions ──────────────────────────────────────────────────────────────────

type Action =
  | { type: 'RESTORE'; session: StoredSession | null }
  | { type: 'LOGIN'; session: StoredSession }
  | { type: 'LOGOUT' }
  | { type: 'UPDATE_CACHES'; session: StoredSession };

function reducer(state: SessionState, action: Action): SessionState {
  switch (action.type) {
    case 'RESTORE':
      return { isLoaded: true, session: action.session };
    case 'LOGIN':
    case 'UPDATE_CACHES':
      return { ...state, session: action.session };
    case 'LOGOUT':
      return { ...state, session: null };
    default:
      return state;
  }
}

// ─── Context ──────────────────────────────────────────────────────────────────

interface SessionContextValue {
  state: SessionState;
  login: (session: StoredSession) => void;
  logout: () => void;
  /** Persist updated cache fields back to storage and context. */
  updateCaches: (patches: Partial<Pick<StoredSession, 'peerDhCache' | 'peerUsernames' | 'userDeviceCache'>>) => void;
}

const SessionContext = createContext<SessionContextValue | null>(null);

// ─── Provider ─────────────────────────────────────────────────────────────────

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reducer, { isLoaded: false, session: null });

  // Restore persisted session on mount.
  useEffect(() => {
    dispatch({ type: 'RESTORE', session: loadSession() });
  }, []);

  // Persist whenever session changes.
  useEffect(() => {
    if (!state.isLoaded) return;
    if (state.session) saveSession(state.session);
    else clearSession();
  }, [state.isLoaded, state.session]);

  function login(session: StoredSession) {
    dispatch({ type: 'LOGIN', session });
  }

  function logout() {
    dispatch({ type: 'LOGOUT' });
  }

  function updateCaches(
    patches: Partial<Pick<StoredSession, 'peerDhCache' | 'peerUsernames' | 'userDeviceCache'>>,
  ) {
    if (!state.session) return;
    const updated = { ...state.session, ...patches };
    dispatch({ type: 'UPDATE_CACHES', session: updated });
  }

  return (
    <SessionContext.Provider value={{ state, login, logout, updateCaches }}>
      {children}
    </SessionContext.Provider>
  );
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useSession() {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error('useSession must be used inside SessionProvider');
  return ctx;
}

/** Convenience: returns the session or throws if not logged in. */
export function useRequiredSession(): StoredSession {
  const { state } = useSession();
  if (!state.session) throw new Error('No active session');
  return state.session;
}
