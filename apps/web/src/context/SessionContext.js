import { jsx as _jsx } from "react/jsx-runtime";
import { createContext, useContext, useReducer, useEffect } from 'react';
import { loadSession, saveSession, clearSession } from '../storage';
function reducer(state, action) {
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
const SessionContext = createContext(null);
// ─── Provider ─────────────────────────────────────────────────────────────────
export function SessionProvider({ children }) {
    const [state, dispatch] = useReducer(reducer, { isLoaded: false, session: null });
    // Restore persisted session on mount.
    useEffect(() => {
        dispatch({ type: 'RESTORE', session: loadSession() });
    }, []);
    // Persist whenever session changes.
    useEffect(() => {
        if (!state.isLoaded)
            return;
        if (state.session)
            saveSession(state.session);
        else
            clearSession();
    }, [state.isLoaded, state.session]);
    function login(session) {
        dispatch({ type: 'LOGIN', session });
    }
    function logout() {
        dispatch({ type: 'LOGOUT' });
    }
    function updateCaches(patches) {
        if (!state.session)
            return;
        const updated = { ...state.session, ...patches };
        dispatch({ type: 'UPDATE_CACHES', session: updated });
    }
    return (_jsx(SessionContext.Provider, { value: { state, login, logout, updateCaches }, children: children }));
}
// ─── Hook ─────────────────────────────────────────────────────────────────────
export function useSession() {
    const ctx = useContext(SessionContext);
    if (!ctx)
        throw new Error('useSession must be used inside SessionProvider');
    return ctx;
}
/** Convenience: returns the session or throws if not logged in. */
export function useRequiredSession() {
    const { state } = useSession();
    if (!state.session)
        throw new Error('No active session');
    return state.session;
}
