import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { useRequiredSession } from '../../context/SessionContext';
import { getUser, inviteToServer } from '../../api';
import Modal from './Modal';
export default function InviteModal({ serverId, onClose }) {
    const [username, setUsername] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [loading, setLoading] = useState(false);
    const session = useRequiredSession();
    async function handleSubmit(e) {
        e.preventDefault();
        const target = username.trim();
        if (!target)
            return;
        setError('');
        setSuccess('');
        setLoading(true);
        try {
            const user = await getUser(session.token, target);
            await inviteToServer(session.token, serverId, { user_id: user.user_id });
            setSuccess(`${target} has been invited!`);
            setUsername('');
        }
        catch (err) {
            setError(err instanceof Error ? err.message : 'Invite failed');
        }
        finally {
            setLoading(false);
        }
    }
    return (_jsx(Modal, { title: "Invite to Server", onClose: onClose, children: _jsxs("form", { onSubmit: handleSubmit, className: "space-y-4", children: [_jsxs("div", { children: [_jsx("label", { className: "mb-1 block text-xs font-medium uppercase tracking-wide text-gray-400", children: "Username" }), _jsx("input", { autoFocus: true, type: "text", value: username, onChange: e => setUsername(e.target.value), placeholder: "Enter a username", className: "w-full rounded-lg bg-surface-700 px-4 py-2.5 text-sm text-white placeholder-gray-500 outline-none ring-1 ring-surface-500 focus:ring-brand-500" })] }), error && _jsx("p", { className: "text-sm text-red-400", children: error }), success && _jsx("p", { className: "text-sm text-green-400", children: success }), _jsxs("div", { className: "flex justify-end gap-2", children: [_jsx("button", { type: "button", onClick: onClose, className: "btn-secondary", children: "Done" }), _jsx("button", { type: "submit", disabled: loading || !username.trim(), className: "btn-primary", children: loading ? 'Inviting…' : 'Invite' })] })] }) }));
}
