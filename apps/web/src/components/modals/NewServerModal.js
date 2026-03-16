import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { useRequiredSession } from '../../context/SessionContext';
import { createServer } from '../../api';
import Modal from './Modal';
export default function NewServerModal({ onClose, onCreated }) {
    const [name, setName] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const session = useRequiredSession();
    async function handleSubmit(e) {
        e.preventDefault();
        const trimmed = name.trim();
        if (!trimmed)
            return;
        setError('');
        setLoading(true);
        try {
            await createServer(session.token, { name: trimmed });
            onCreated();
        }
        catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to create server');
        }
        finally {
            setLoading(false);
        }
    }
    return (_jsx(Modal, { title: "Create Server", onClose: onClose, children: _jsxs("form", { onSubmit: handleSubmit, className: "space-y-4", children: [_jsxs("div", { children: [_jsx("label", { className: "mb-1 block text-xs font-medium uppercase tracking-wide text-gray-400", children: "Server Name" }), _jsx("input", { autoFocus: true, type: "text", value: name, onChange: e => setName(e.target.value), placeholder: "My Awesome Server", maxLength: 100, className: "w-full rounded-lg bg-surface-700 px-4 py-2.5 text-sm text-white placeholder-gray-500 outline-none ring-1 ring-surface-500 focus:ring-brand-500" })] }), error && _jsx("p", { className: "text-sm text-red-400", children: error }), _jsxs("div", { className: "flex justify-end gap-2", children: [_jsx("button", { type: "button", onClick: onClose, className: "btn-secondary", children: "Cancel" }), _jsx("button", { type: "submit", disabled: loading || !name.trim(), className: "btn-primary", children: loading ? 'Creating…' : 'Create' })] })] }) }));
}
