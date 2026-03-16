import { useState, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useRequiredSession, useSession } from '../context/SessionContext';
import {
  sendDmMessage, sendChannelMessage, resolveUserDevice, getServer, buildEnvelopes,
} from '../api';
import { uuidToBytes } from '../crypto';
import type { Recipient } from '../api';

interface DmInputProps {
  kind: 'dm';
  id: string;               // thread_id
  recipientUsername: string;
  placeholder: string;
}

interface ChannelInputProps {
  kind: 'channel';
  id: string;               // channel_id
  serverId: string;
  placeholder: string;
}

type Props = DmInputProps | ChannelInputProps;

export default function MessageInput(props: Props) {
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const session = useRequiredSession();
  const { updateCaches } = useSession();
  const queryClient = useQueryClient();
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  async function handleSend() {
    const trimmed = text.trim();
    if (!trimmed || sending) return;
    setError('');
    setSending(true);

    try {
      const aad = uuidToBytes(props.id);
      const peerDhCache = { ...session.peerDhCache };
      const peerUsernames = { ...session.peerUsernames };
      const userDeviceCache = { ...session.userDeviceCache };

      let recipients: Recipient[] = [];

      if (props.kind === 'dm') {
        // Resolve the recipient's device key (cached or fetched).
        // Try to find the recipient by username from userDeviceCache via peerUsernames.
        let devId: string | undefined;
        let dhPub: string | undefined;
        for (const [uid, [d, k]] of Object.entries(userDeviceCache)) {
          if (peerUsernames[uid] === props.recipientUsername) {
            devId = d;
            dhPub = k;
            break;
          }
        }
        if (!devId || !dhPub) {
          const resolved = await resolveUserDevice(session.token, props.recipientUsername);
          devId = resolved.deviceId;
          dhPub = resolved.dhPublicB64;
          peerDhCache[devId] = dhPub;
          userDeviceCache[resolved.userId] = [devId, dhPub];
          peerUsernames[resolved.userId] = props.recipientUsername;
        }
        recipients = [{ deviceId: devId, dhPublicB64: dhPub }];

      } else {
        // Channel: encrypt for all server members.
        const serverDetails = await getServer(session.token, props.serverId);
        for (const member of serverDetails.members) {
          if (member.user_id === session.userId) continue;
          const cached = userDeviceCache[member.user_id];
          if (cached) {
            recipients.push({ deviceId: cached[0], dhPublicB64: cached[1] });
          } else {
            try {
              const resolved = await resolveUserDevice(session.token, member.username);
              peerDhCache[resolved.deviceId] = resolved.dhPublicB64;
              userDeviceCache[member.user_id] = [resolved.deviceId, resolved.dhPublicB64];
              peerUsernames[member.user_id] = member.username;
              recipients.push({ deviceId: resolved.deviceId, dhPublicB64: resolved.dhPublicB64 });
            } catch { /* member may have no device yet */ }
          }
        }
      }

      const envelopes = buildEnvelopes(
        session.dhSecretB64, session.deviceId, trimmed, aad, recipients,
      );

      if (props.kind === 'dm') {
        await sendDmMessage(session.token, props.id, {
          sender_device_id: session.deviceId,
          envelopes,
        });
      } else {
        await sendChannelMessage(session.token, props.id, {
          sender_device_id: session.deviceId,
          envelopes,
        });
      }

      updateCaches({ peerDhCache, peerUsernames, userDeviceCache });
      setText('');

      // Invalidate the message query so MessageList picks up the new message.
      queryClient.invalidateQueries({ queryKey: ['messages', props.kind, props.id] });

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send');
    } finally {
      setSending(false);
      textareaRef.current?.focus();
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  return (
    <div className="border-t border-surface-600 px-4 py-3">
      {error && (
        <p className="mb-2 rounded bg-red-500/10 px-3 py-1.5 text-xs text-red-400">{error}</p>
      )}
      <div className="flex items-end gap-2 rounded-xl bg-surface-700 px-3 py-2">
        <textarea
          ref={textareaRef}
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={props.placeholder}
          rows={1}
          className="flex-1 resize-none bg-transparent text-sm text-white placeholder-gray-500 outline-none"
          style={{ maxHeight: '120px' }}
        />
        <button
          onClick={handleSend}
          disabled={!text.trim() || sending}
          className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-lg bg-brand-500 text-sm text-white transition-colors hover:bg-brand-600 disabled:opacity-40"
        >
          ↵
        </button>
      </div>
      <p className="mt-1 text-right text-[10px] text-gray-600">
        Enter to send · Shift+Enter for new line
      </p>
    </div>
  );
}
