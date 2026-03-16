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
import type { ChannelSummary } from '../types';

// ─── View discriminant ────────────────────────────────────────────────────────

type ActiveView =
  | { kind: 'none' }
  | { kind: 'dm'; threadId: string; otherUsername: string; otherUserId: string }
  | { kind: 'channel'; serverId: string; serverName: string; channel: ChannelSummary };

export type Modal =
  | { kind: 'newDm' }
  | { kind: 'newServer' }
  | { kind: 'newChannel'; serverId: string }
  | { kind: 'invite'; serverId: string };

export default function AppPage() {
  const session = useRequiredSession();
  const { logout } = useSession();

  const [activeView, setActiveView] = useState<ActiveView>({ kind: 'none' });
  const [modal, setModal] = useState<Modal | null>(null);
  const [selectedServerId, setSelectedServerId] = useState<string | null>(null);

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
    try { await apiLogout(session.token); } catch { /* ignore */ }
    logout();
  }

  const activeChannel =
    activeView.kind === 'channel' ? activeView.channel : null;
  const activeServerId =
    activeView.kind === 'channel' ? activeView.serverId : selectedServerId;

  return (
    <div className="flex h-full overflow-hidden bg-surface-900">
      {/* Column 1 — server icons + DM/channel list */}
      <Sidebar
        username={session.username}
        dms={dmsQuery.data ?? []}
        servers={serversQuery.data ?? []}
        activeView={activeView}
        selectedServerId={activeServerId}
        onSelectDm={(threadId, otherUsername, otherUserId) =>
          setActiveView({ kind: 'dm', threadId, otherUsername, otherUserId })
        }
        onSelectServer={id => {
          setSelectedServerId(id);
          // If currently viewing a channel from a different server, reset.
          if (activeView.kind === 'channel' && activeView.serverId !== id) {
            setActiveView({ kind: 'none' });
          }
        }}
        onSelectChannel={(serverId, serverName, channel) =>
          setActiveView({ kind: 'channel', serverId, serverName, channel })
        }
        onNewDm={() => setModal({ kind: 'newDm' })}
        onNewServer={() => setModal({ kind: 'newServer' })}
        onNewChannel={serverId => setModal({ kind: 'newChannel', serverId })}
        onInvite={serverId => setModal({ kind: 'invite', serverId })}
        onLogout={handleLogout}
      />

      {/* Column 2 — message area */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {activeView.kind === 'none' && (
          <div className="flex flex-1 items-center justify-center text-gray-500">
            Select a conversation or channel to get started
          </div>
        )}

        {activeView.kind === 'dm' && (
          <>
            <ChatHeader title={`@${activeView.otherUsername}`} />
            <MessageList
              kind="dm"
              id={activeView.threadId}
              otherUserId={activeView.otherUserId}
              otherUsername={activeView.otherUsername}
            />
            <MessageInput
              kind="dm"
              id={activeView.threadId}
              recipientUsername={activeView.otherUsername}
              placeholder={`Message @${activeView.otherUsername}`}
            />
          </>
        )}

        {activeView.kind === 'channel' && activeChannel && (
          <>
            <ChatHeader
              title={`#${activeChannel.name}`}
              subtitle={activeView.serverName}
            />
            <MessageList
              kind="channel"
              id={activeChannel.channel_id}
              serverId={activeView.serverId}
            />
            <MessageInput
              kind="channel"
              id={activeChannel.channel_id}
              serverId={activeView.serverId}
              placeholder={`Message #${activeChannel.name}`}
            />
          </>
        )}
      </div>

      {/* Modals */}
      {modal?.kind === 'newDm' && (
        <NewDmModal
          onClose={() => setModal(null)}
          onOpened={(threadId, otherUsername, otherUserId) => {
            setModal(null);
            setActiveView({ kind: 'dm', threadId, otherUsername, otherUserId });
          }}
        />
      )}
      {modal?.kind === 'newServer' && (
        <NewServerModal
          onClose={() => setModal(null)}
          onCreated={() => {
            setModal(null);
            serversQuery.refetch();
          }}
        />
      )}
      {modal?.kind === 'newChannel' && (
        <NewChannelModal
          serverId={modal.serverId}
          onClose={() => setModal(null)}
          onCreated={() => setModal(null)}
        />
      )}
      {modal?.kind === 'invite' && (
        <InviteModal
          serverId={modal.serverId}
          onClose={() => setModal(null)}
        />
      )}
    </div>
  );
}

function ChatHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="flex items-center gap-2 border-b border-surface-600 px-4 py-3">
      <span className="font-semibold text-white">{title}</span>
      {subtitle && <span className="text-sm text-gray-400">in {subtitle}</span>}
    </div>
  );
}
