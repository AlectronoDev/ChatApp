import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect } from 'react';
export default function Modal({ title, onClose, children }) {
    // Close on Escape.
    useEffect(() => {
        function handler(e) {
            if (e.key === 'Escape')
                onClose();
        }
        window.addEventListener('keydown', handler);
        return () => window.removeEventListener('keydown', handler);
    }, [onClose]);
    return (_jsx("div", { className: "fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm", onClick: e => { if (e.target === e.currentTarget)
            onClose(); }, children: _jsxs("div", { className: "w-full max-w-md rounded-xl bg-surface-800 p-6 shadow-2xl", children: [_jsxs("div", { className: "mb-4 flex items-center justify-between", children: [_jsx("h2", { className: "text-lg font-semibold text-white", children: title }), _jsx("button", { onClick: onClose, className: "rounded p-1 text-gray-400 hover:text-white", children: "\u2715" })] }), children] }) }));
}
