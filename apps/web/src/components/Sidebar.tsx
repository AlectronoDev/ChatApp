import { useQuery } from '@tanstack/react-query';
import { useRequiredSession } from '../context/SessionContext';
import { listChannels } from '../api';
import type { DmThreadSummary, ServerSummary, ChannelSummary } from '../types';

interface Props {
  username: string;
  dms: DmThreadSummary[];
  servers: ServerSummary[];
  activeView: { kind: string; threadId?: string; channel?: ChannelSummary };
  selectedServerId: string | null;
  onSelectDm: (threadId: string, otherUsername: string, otherUserId: string) => void;
  onSelectServer: (serverId: string) => void;
  onSelectChannel: (serverId: string, serverName: string, channel: ChannelSummary) => void;
  onNewDm: () => void;
  onNewServer: () => void;
  onNewChannel: (serverId: string) => void;
  onInvite: (serverId: string) => void;
  onLogout: () => void;
}

export default function Sidebar({
  username, dms, servers, activeView, selectedServerId,
  onSelectDm, onSelectServer, onSelectChannel,
  onNewDm, onNewServer, onNewChannel, onInvite, onLogout,
}: Props) {
  return (
    <div className="flex h-full w-60 flex-shrink-0 flex-col border-r border-surface-600 bg-surface-800">
      {/* User bar */}
      <div className="flex items-center justify-between border-b border-surface-600 px-3 py-2">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-500 text-xs font-bold uppercase">
            {username[0]}
          </div>
          <span className="text-sm font-medium text-white">{username}</span>
        </div>
        <button
          onClick={onLogout}
          title="Log out"
          className="rounded p-1 text-gray-400 hover:text-white"
        >
          ↩
        </button>
      </div>

      <div className="flex flex-1 flex-col overflow-y-auto scrollbar-thin">
        {/* Direct Messages */}
        <Section
          label="Direct Messages"
          action={<AddButton onClick={onNewDm} title="New DM" />}
        >
          {dms.length === 0 && (
            <p className="px-3 py-1 text-xs text-gray-500">No conversations yet</p>
          )}
          {dms.map(dm => (
            <NavItem
              key={dm.thread_id}
              active={activeView.kind === 'dm' && activeView.threadId === dm.thread_id}
              onClick={() => onSelectDm(dm.thread_id, dm.other_user.username, dm.other_user.user_id)}
            >
              <span className="mr-1.5 text-gray-400">@</span>
              {dm.other_user.username}
            </NavItem>
          ))}
        </Section>

        {/* Servers */}
        <Section
          label="Servers"
          action={<AddButton onClick={onNewServer} title="New Server" />}
        >
          {servers.length === 0 && (
            <p className="px-3 py-1 text-xs text-gray-500">No servers yet</p>
          )}
          {servers.map(server => (
            <ServerEntry
              key={server.server_id}
              server={server}
              isSelected={selectedServerId === server.server_id}
              activeChannelId={
                activeView.kind === 'channel' && activeView.channel
                  ? activeView.channel.channel_id
                  : null
              }
              onSelect={() => onSelectServer(server.server_id)}
              onSelectChannel={ch => onSelectChannel(server.server_id, server.name, ch)}
              onNewChannel={() => onNewChannel(server.server_id)}
              onInvite={() => onInvite(server.server_id)}
            />
          ))}
        </Section>
      </div>
    </div>
  );
}

// ─── Server entry with collapsible channel list ───────────────────────────────

function ServerEntry({
  server, isSelected, activeChannelId,
  onSelect, onSelectChannel, onNewChannel, onInvite,
}: {
  server: ServerSummary;
  isSelected: boolean;
  activeChannelId: string | null;
  onSelect: () => void;
  onSelectChannel: (ch: ChannelSummary) => void;
  onNewChannel: () => void;
  onInvite: () => void;
}) {
  const session = useRequiredSession();

  const channelsQuery = useQuery({
    queryKey: ['channels', server.server_id, session.token],
    queryFn: () => listChannels(session.token, server.server_id),
    enabled: isSelected,
  });

  return (
    <div>
      <button
        onClick={onSelect}
        className={`flex w-full items-center justify-between px-3 py-1.5 text-left text-sm transition-colors ${
          isSelected
            ? 'bg-surface-600 text-white'
            : 'text-gray-300 hover:bg-surface-700 hover:text-white'
        }`}
      >
        <span className="truncate font-medium">{server.name}</span>
        <span className="ml-1 text-xs text-gray-500">{isSelected ? '▾' : '▸'}</span>
      </button>

      {isSelected && (
        <div className="pl-2">
          {channelsQuery.data?.map(ch => (
            <NavItem
              key={ch.channel_id}
              active={activeChannelId === ch.channel_id}
              onClick={() => onSelectChannel(ch)}
            >
              <span className="mr-1 text-gray-500">#</span>
              {ch.name}
            </NavItem>
          ))}

          {/* Owner actions */}
          {server.role === 'owner' && (
            <div className="mt-1 flex gap-1 px-2 pb-1">
              <ActionChip onClick={onNewChannel}>+ Channel</ActionChip>
              <ActionChip onClick={onInvite}>+ Invite</ActionChip>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Small helpers ────────────────────────────────────────────────────────────

function Section({
  label, action, children,
}: { label: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="mt-2">
      <div className="flex items-center justify-between px-3 pb-1">
        <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
          {label}
        </span>
        {action}
      </div>
      {children}
    </div>
  );
}

function NavItem({
  active, onClick, children,
}: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`flex w-full items-center truncate rounded px-3 py-1.5 text-left text-sm transition-colors ${
        active
          ? 'bg-surface-500 text-white'
          : 'text-gray-400 hover:bg-surface-700 hover:text-white'
      }`}
    >
      {children}
    </button>
  );
}

function AddButton({ onClick, title }: { onClick: () => void; title: string }) {
  return (
    <button
      onClick={onClick}
      title={title}
      className="rounded p-0.5 text-gray-400 hover:text-white"
    >
      +
    </button>
  );
}

function ActionChip({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className="rounded bg-surface-600 px-2 py-0.5 text-xs text-gray-300 hover:bg-surface-500 hover:text-white"
    >
      {children}
    </button>
  );
}
