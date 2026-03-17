import { jsx as _jsx, Fragment as _Fragment, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRequiredSession, useSession } from '../context/SessionContext';
import { listDms, listServers, logout as apiLogout } from '../api';
import Sidebar from '../components/Sidebar';
import MessageList from '../components/MessageList';
import MessageInput from '../components/MessageInput';
import NewDmModal from '../components/modals/NewDmModal';
import NewServerModal from '../components/modals/NewServerModal';
import NewChannelModal from '../components/modals/NewChannelModal';
import InviteModal from '../components/modals/InviteModal';
export default function AppPage() {
    const session = useRequiredSession();
    const { logout } = useSession();
    const [activeView, setActiveView] = useState({ kind: 'none' });
    const [modal, setModal] = useState(null);
    const [selectedServerId, setSelectedServerId] = useState(null);
    const dmsQuery = useQuery({
        queryKey: ['dms', session.token],
        queryFn: () => listDms(session.token),
        refetchInterval: 5000,
    });
    const serversQuery = useQuery({
        queryKey: ['servers', session.token],
        queryFn: () => listServers(session.token),
        refetchInterval: 10000,
    });
    async function handleLogout() {
        try {
            await apiLogout(session.token);
        }
        catch { /* ignore */ }
        logout();
    }
    const activeChannel = activeView.kind === 'channel' ? activeView.channel : null;
    const activeServerId = activeView.kind === 'channel' ? activeView.serverId : selectedServerId;
    return (_jsxs("div", { className: "flex h-full overflow-hidden bg-surface-900", children: [_jsx(Sidebar, { username: session.username, dms: dmsQuery.data ?? [], servers: serversQuery.data ?? [], activeView: activeView, selectedServerId: activeServerId, onSelectDm: (threadId, otherUsername, otherUserId) => setActiveView({ kind: 'dm', threadId, otherUsername, otherUserId }), onSelectServer: id => {
                    setSelectedServerId(id);
                    // If currently viewing a channel from a different server, reset.
                    if (activeView.kind === 'channel' && activeView.serverId !== id) {
                        setActiveView({ kind: 'none' });
                    }
                }, onSelectChannel: (serverId, serverName, channel) => setActiveView({ kind: 'channel', serverId, serverName, channel }), onNewDm: () => setModal({ kind: 'newDm' }), onNewServer: () => setModal({ kind: 'newServer' }), onNewChannel: serverId => setModal({ kind: 'newChannel', serverId }), onInvite: serverId => setModal({ kind: 'invite', serverId }), onLogout: handleLogout }), _jsxs("div", { className: "flex flex-1 flex-col overflow-hidden", children: [activeView.kind === 'none' && (_jsx("div", { className: "flex flex-1 items-center justify-center text-gray-500", children: "Select a conversation or channel to get started" })), activeView.kind === 'dm' && (_jsxs(_Fragment, { children: [_jsx(ChatHeader, { title: `@${activeView.otherUsername}` }), _jsx(MessageList, { kind: "dm", id: activeView.threadId, otherUserId: activeView.otherUserId, otherUsername: activeView.otherUsername }), _jsx(MessageInput, { kind: "dm", id: activeView.threadId, recipientUsername: activeView.otherUsername, placeholder: `Message @${activeView.otherUsername}` })] })), activeView.kind === 'channel' && activeChannel && (_jsxs(_Fragment, { children: [_jsx(ChatHeader, { title: `#${activeChannel.name}`, subtitle: activeView.serverName }), _jsx(MessageList, { kind: "channel", id: activeChannel.channel_id, serverId: activeView.serverId }), _jsx(MessageInput, { kind: "channel", id: activeChannel.channel_id, serverId: activeView.serverId, placeholder: `Message #${activeChannel.name}` })] }))] }), modal?.kind === 'newDm' && (_jsx(NewDmModal, { onClose: () => setModal(null), onOpened: (threadId, otherUsername, otherUserId) => {
                    setModal(null);
                    setActiveView({ kind: 'dm', threadId, otherUsername, otherUserId });
                } })), modal?.kind === 'newServer' && (_jsx(NewServerModal, { onClose: () => setModal(null), onCreated: () => {
                    setModal(null);
                    serversQuery.refetch();
                } })), modal?.kind === 'newChannel' && (_jsx(NewChannelModal, { serverId: modal.serverId, onClose: () => setModal(null), onCreated: () => setModal(null) })), modal?.kind === 'invite' && (_jsx(InviteModal, { serverId: modal.serverId, onClose: () => setModal(null) }))] }));
}
function ChatHeader({ title, subtitle }) {
    return (_jsxs("div", { className: "flex items-center gap-2 border-b border-surface-600 px-4 py-3", children: [_jsx("span", { className: "font-semibold text-white", children: title }), subtitle && _jsxs("span", { className: "text-sm text-gray-400", children: ["in ", subtitle] })] }));
}
