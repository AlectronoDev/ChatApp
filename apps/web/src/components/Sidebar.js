import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useQuery } from '@tanstack/react-query';
import { useRequiredSession } from '../context/SessionContext';
import { listChannels } from '../api';
export default function Sidebar({ username, dms, servers, activeView, selectedServerId, onSelectDm, onSelectServer, onSelectChannel, onNewDm, onNewServer, onNewChannel, onInvite, onLogout, }) {
    return (_jsxs("div", { className: "flex h-full w-60 flex-shrink-0 flex-col border-r border-surface-600 bg-surface-800", children: [_jsxs("div", { className: "flex items-center justify-between border-b border-surface-600 px-3 py-2", children: [_jsxs("div", { className: "flex items-center gap-2", children: [_jsx("div", { className: "flex h-8 w-8 items-center justify-center rounded-full bg-brand-500 text-xs font-bold uppercase", children: username[0] }), _jsx("span", { className: "text-sm font-medium text-white", children: username })] }), _jsx("button", { onClick: onLogout, title: "Log out", className: "rounded p-1 text-gray-400 hover:text-white", children: "\u21A9" })] }), _jsxs("div", { className: "flex flex-1 flex-col overflow-y-auto scrollbar-thin", children: [_jsxs(Section, { label: "Direct Messages", action: _jsx(AddButton, { onClick: onNewDm, title: "New DM" }), children: [dms.length === 0 && (_jsx("p", { className: "px-3 py-1 text-xs text-gray-500", children: "No conversations yet" })), dms.map(dm => (_jsxs(NavItem, { active: activeView.kind === 'dm' && activeView.threadId === dm.thread_id, onClick: () => onSelectDm(dm.thread_id, dm.other_user.username, dm.other_user.user_id), children: [_jsx("span", { className: "mr-1.5 text-gray-400", children: "@" }), dm.other_user.username] }, dm.thread_id)))] }), _jsxs(Section, { label: "Servers", action: _jsx(AddButton, { onClick: onNewServer, title: "New Server" }), children: [servers.length === 0 && (_jsx("p", { className: "px-3 py-1 text-xs text-gray-500", children: "No servers yet" })), servers.map(server => (_jsx(ServerEntry, { server: server, isSelected: selectedServerId === server.server_id, activeChannelId: activeView.kind === 'channel' && activeView.channel
                                    ? activeView.channel.channel_id
                                    : null, onSelect: () => onSelectServer(server.server_id), onSelectChannel: ch => onSelectChannel(server.server_id, server.name, ch), onNewChannel: () => onNewChannel(server.server_id), onInvite: () => onInvite(server.server_id) }, server.server_id)))] })] })] }));
}
// ─── Server entry with collapsible channel list ───────────────────────────────
function ServerEntry({ server, isSelected, activeChannelId, onSelect, onSelectChannel, onNewChannel, onInvite, }) {
    const session = useRequiredSession();
    const channelsQuery = useQuery({
        queryKey: ['channels', server.server_id, session.token],
        queryFn: () => listChannels(session.token, server.server_id),
        enabled: isSelected,
    });
    return (_jsxs("div", { children: [_jsxs("button", { onClick: onSelect, className: `flex w-full items-center justify-between px-3 py-1.5 text-left text-sm transition-colors ${isSelected
                    ? 'bg-surface-600 text-white'
                    : 'text-gray-300 hover:bg-surface-700 hover:text-white'}`, children: [_jsx("span", { className: "truncate font-medium", children: server.name }), _jsx("span", { className: "ml-1 text-xs text-gray-500", children: isSelected ? '▾' : '▸' })] }), isSelected && (_jsxs("div", { className: "pl-2", children: [channelsQuery.data?.map(ch => (_jsxs(NavItem, { active: activeChannelId === ch.channel_id, onClick: () => onSelectChannel(ch), children: [_jsx("span", { className: "mr-1 text-gray-500", children: "#" }), ch.name] }, ch.channel_id))), server.role === 'owner' && (_jsxs("div", { className: "mt-1 flex gap-1 px-2 pb-1", children: [_jsx(ActionChip, { onClick: onNewChannel, children: "+ Channel" }), _jsx(ActionChip, { onClick: onInvite, children: "+ Invite" })] }))] }))] }));
}
// ─── Small helpers ────────────────────────────────────────────────────────────
function Section({ label, action, children, }) {
    return (_jsxs("div", { className: "mt-2", children: [_jsxs("div", { className: "flex items-center justify-between px-3 pb-1", children: [_jsx("span", { className: "text-xs font-semibold uppercase tracking-wider text-gray-400", children: label }), action] }), children] }));
}
function NavItem({ active, onClick, children, }) {
    return (_jsx("button", { onClick: onClick, className: `flex w-full items-center truncate rounded px-3 py-1.5 text-left text-sm transition-colors ${active
            ? 'bg-surface-500 text-white'
            : 'text-gray-400 hover:bg-surface-700 hover:text-white'}`, children: children }));
}
function AddButton({ onClick, title }) {
    return (_jsx("button", { onClick: onClick, title: title, className: "rounded p-0.5 text-gray-400 hover:text-white", children: "+" }));
}
function ActionChip({ onClick, children }) {
    return (_jsx("button", { onClick: onClick, className: "rounded bg-surface-600 px-2 py-0.5 text-xs text-gray-300 hover:bg-surface-500 hover:text-white", children: children }));
}
