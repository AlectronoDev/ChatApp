import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { useRequiredSession, useSession } from '../../context/SessionContext';
import { getUser, createOrGetDm, resolveUserDevice } from '../../api';
import Modal from './Modal';
export default function NewDmModal({ onClose, onOpened }) {
    const [username, setUsername] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const session = useRequiredSession();
    const { updateCaches } = useSession();
    async function handleSubmit(e) {
        e.preventDefault();
        const target = username.trim();
        if (!target)
            return;
        if (target === session.username) {
            setError("You can't message yourself.");
            return;
        }
        setError('');
        setLoading(true);
        try {
            const user = await getUser(session.token, target);
            const dm = await createOrGetDm(session.token, { with_user_id: user.user_id });
            // Pre-cache the target's device keys.
            try {
                const resolved = await resolveUserDevice(session.token, target);
                updateCaches({
                    peerDhCache: { ...session.peerDhCache, [resolved.deviceId]: resolved.dhPublicB64 },
                    peerUsernames: { ...session.peerUsernames, [user.user_id]: target },
                    userDeviceCache: {
                        ...session.userDeviceCache,
                        [resolved.userId]: [resolved.deviceId, resolved.dhPublicB64],
                    },
                });
            }
            catch { /* keys can be fetched lazily on first send */ }
            onOpened(dm.thread_id, target, user.user_id);
        }
        catch (err) {
            setError(err instanceof Error ? err.message : 'User not found');
        }
        finally {
            setLoading(false);
        }
    }
    return (_jsx(Modal, { title: "New Direct Message", onClose: onClose, children: _jsxs("form", { onSubmit: handleSubmit, className: "space-y-4", children: [_jsxs("div", { children: [_jsx("label", { className: "mb-1 block text-xs font-medium uppercase tracking-wide text-gray-400", children: "Username" }), _jsx("input", { autoFocus: true, type: "text", value: username, onChange: e => setUsername(e.target.value), placeholder: "Enter a username", className: "w-full rounded-lg bg-surface-700 px-4 py-2.5 text-sm text-white placeholder-gray-500 outline-none ring-1 ring-surface-500 focus:ring-brand-500" })] }), error && _jsx("p", { className: "text-sm text-red-400", children: error }), _jsxs("div", { className: "flex justify-end gap-2", children: [_jsx("button", { type: "button", onClick: onClose, className: "btn-secondary", children: "Cancel" }), _jsx("button", { type: "submit", disabled: loading, className: "btn-primary", children: loading ? 'Opening…' : 'Open DM' })] })] }) }));
}
