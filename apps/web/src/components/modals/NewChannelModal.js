import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { useRequiredSession } from '../../context/SessionContext';
import { createChannel } from '../../api';
import { useQueryClient } from '@tanstack/react-query';
import Modal from './Modal';
export default function NewChannelModal({ serverId, onClose, onCreated }) {
    const [name, setName] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const session = useRequiredSession();
    const queryClient = useQueryClient();
    async function handleSubmit(e) {
        e.preventDefault();
        const trimmed = name.trim();
        if (!trimmed)
            return;
        setError('');
        setLoading(true);
        try {
            await createChannel(session.token, serverId, { name: trimmed });
            queryClient.invalidateQueries({ queryKey: ['channels', serverId] });
            onCreated();
        }
        catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to create channel');
        }
        finally {
            setLoading(false);
        }
    }
    return (_jsx(Modal, { title: "Create Channel", onClose: onClose, children: _jsxs("form", { onSubmit: handleSubmit, className: "space-y-4", children: [_jsxs("div", { children: [_jsx("label", { className: "mb-1 block text-xs font-medium uppercase tracking-wide text-gray-400", children: "Channel Name" }), _jsxs("div", { className: "flex items-center rounded-lg bg-surface-700 ring-1 ring-surface-500 focus-within:ring-brand-500", children: [_jsx("span", { className: "pl-3 text-gray-500", children: "#" }), _jsx("input", { autoFocus: true, type: "text", value: name, onChange: e => setName(e.target.value.toLowerCase().replace(/\s+/g, '-')), placeholder: "general", maxLength: 100, className: "flex-1 bg-transparent px-2 py-2.5 text-sm text-white placeholder-gray-500 outline-none" })] })] }), error && _jsx("p", { className: "text-sm text-red-400", children: error }), _jsxs("div", { className: "flex justify-end gap-2", children: [_jsx("button", { type: "button", onClick: onClose, className: "btn-secondary", children: "Cancel" }), _jsx("button", { type: "submit", disabled: loading || !name.trim(), className: "btn-primary", children: loading ? 'Creating…' : 'Create Channel' })] })] }) }));
}
