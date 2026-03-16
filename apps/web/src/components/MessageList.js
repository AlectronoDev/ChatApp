import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useRequiredSession, useSession } from '../context/SessionContext';
import { fetchDmMessages, fetchChannelMessages, ackDmMessages, ackChannelMessages, getDevicePublicInfo, } from '../api';
import { decryptFromDevice, dhPublicKeyB64, uuidToBytes } from '../crypto';
export default function MessageList(props) {
    const session = useRequiredSession();
    const { updateCaches } = useSession();
    const bottomRef = useRef(null);
    // Cursor for incremental polling — advances after each successful fetch.
    const [cursor, setCursor] = useState(undefined);
    // Accumulate decrypted messages client-side.
    const [messages, setMessages] = useState([]);
    // ─── Fetch raw envelopes ───────────────────────────────────────────────────
    const fetchFn = props.kind === 'dm'
        ? () => fetchDmMessages(session.token, props.id, session.deviceId, cursor)
        : () => fetchChannelMessages(session.token, props.id, session.deviceId, cursor);
    const { data: raw } = useQuery({
        queryKey: ['messages', props.kind, props.id, cursor],
        queryFn: fetchFn,
        refetchInterval: 2000,
        // Don't refetch while a stale result is shown — let the cursor drive it.
        staleTime: 0,
    });
    // ─── Decrypt and append new messages ──────────────────────────────────────
    useEffect(() => {
        if (!raw?.messages.length)
            return;
        (async () => {
            const newMessages = [];
            const ackIds = [];
            // Mutable local copies of the caches so we can update them in one batch.
            const peerDhCache = { ...session.peerDhCache };
            const peerUsernames = { ...session.peerUsernames };
            for (const msg of raw.messages) {
                const aad = uuidToBytes(props.id);
                const isSelf = msg.sender_user_id === session.userId;
                // Resolve sender DH public key.
                let senderDhPub;
                if (isSelf) {
                    senderDhPub = dhPublicKeyB64(session.dhSecretB64);
                }
                else {
                    const cached = peerDhCache[msg.sender_device_id];
                    if (cached) {
                        senderDhPub = cached;
                    }
                    else {
                        try {
                            const info = await getDevicePublicInfo(session.token, msg.sender_device_id);
                            senderDhPub = info.identity_dh_key;
                            peerDhCache[msg.sender_device_id] = senderDhPub;
                        }
                        catch {
                            newMessages.push(errMessage(msg, '[key lookup failed]'));
                            ackIds.push(msg.batch_id);
                            continue;
                        }
                    }
                }
                // Resolve sender username.  For DMs we already have the other party's
                // username from the thread summary — use it directly to avoid depending
                // on the cache being populated on a fresh session.
                const senderUsername = isSelf
                    ? session.username
                    : (props.kind === 'dm' && msg.sender_user_id === props.otherUserId
                        ? props.otherUsername
                        : (peerUsernames[msg.sender_user_id] ?? `user:${msg.sender_user_id.slice(0, 8)}`));
                // Keep cache up-to-date for channel messages.
                if (!isSelf && !peerUsernames[msg.sender_user_id] && senderUsername !== `user:${msg.sender_user_id.slice(0, 8)}`) {
                    peerUsernames[msg.sender_user_id] = senderUsername;
                }
                // Decrypt.
                let plaintext;
                try {
                    plaintext = decryptFromDevice(session.dhSecretB64, senderDhPub, msg.ciphertext, aad);
                }
                catch {
                    plaintext = '[decryption failed]';
                }
                newMessages.push({
                    batchId: msg.batch_id,
                    senderUserId: msg.sender_user_id,
                    senderUsername,
                    plaintext,
                    createdAt: new Date(msg.created_at),
                });
                ackIds.push(msg.batch_id);
            }
            // Persist updated caches.
            updateCaches({ peerDhCache, peerUsernames });
            // ACK delivered messages (fire-and-forget).
            if (ackIds.length) {
                const ackBody = { device_id: session.deviceId, batch_ids: ackIds };
                if (props.kind === 'dm')
                    ackDmMessages(session.token, props.id, ackBody).catch(() => { });
                else
                    ackChannelMessages(session.token, props.id, ackBody).catch(() => { });
            }
            // Append only truly new messages (dedupe by batchId).
            setMessages(prev => {
                const seen = new Set(prev.map(m => m.batchId));
                const fresh = newMessages.filter(m => !seen.has(m.batchId));
                if (!fresh.length)
                    return prev;
                return [...prev, ...fresh];
            });
            // Advance cursor to the last batch_id.
            const last = raw.messages[raw.messages.length - 1];
            if (last)
                setCursor(last.batch_id);
        })();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [raw]);
    // Reset when switching conversations.
    useEffect(() => {
        setMessages([]);
        setCursor(undefined);
    }, [props.id]);
    // Auto-scroll to bottom when new messages arrive.
    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);
    // ─── Render ───────────────────────────────────────────────────────────────
    return (_jsxs("div", { className: "flex flex-1 flex-col-reverse overflow-y-auto scrollbar-thin px-4 py-2", children: [_jsx("div", { ref: bottomRef }), messages.length === 0 && (_jsx("p", { className: "py-8 text-center text-sm text-gray-500", children: "No messages yet. Say hello!" })), [...messages].reverse().map(msg => (_jsx(MessageBubble, { msg: msg, isSelf: msg.senderUserId === session.userId }, msg.batchId)))] }));
}
function MessageBubble({ msg, isSelf }) {
    const time = msg.createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return (_jsxs("div", { className: `mb-1 flex items-start gap-2 ${isSelf ? 'flex-row-reverse' : ''}`, children: [_jsx("div", { className: "mt-0.5 flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full bg-surface-500 text-xs font-bold uppercase", children: msg.senderUsername[0] }), _jsxs("div", { className: `max-w-[75%] ${isSelf ? 'items-end' : 'items-start'} flex flex-col`, children: [_jsxs("div", { className: `flex items-baseline gap-2 ${isSelf ? 'flex-row-reverse' : ''}`, children: [_jsx("span", { className: "text-xs font-semibold text-gray-300", children: msg.senderUsername }), _jsx("span", { className: "text-[10px] text-gray-500", children: time })] }), _jsx("div", { className: `mt-0.5 rounded-2xl px-3 py-1.5 text-sm ${isSelf
                            ? 'rounded-tr-sm bg-brand-500 text-white'
                            : 'rounded-tl-sm bg-surface-600 text-gray-100'}`, children: msg.plaintext })] })] }));
}
function errMessage(raw, reason) {
    return {
        batchId: raw.batch_id,
        senderUserId: raw.sender_user_id,
        senderUsername: `user:${raw.sender_user_id.slice(0, 8)}`,
        plaintext: reason,
        createdAt: new Date(raw.created_at),
    };
}
