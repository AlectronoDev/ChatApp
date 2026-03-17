import { useState } from 'react';
import { useRequiredSession, useSession } from '../../context/SessionContext';
import { getUser, createOrGetDm, resolveUserDevice } from '../../api';
import Modal from './Modal';

interface Props {
  onClose: () => void;
  onOpened: (threadId: string, otherUsername: string, otherUserId: string) => void;
}

export default function NewDmModal({ onClose, onOpened }: Props) {
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const session = useRequiredSession();
  const { updateCaches } = useSession();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const target = username.trim();
    if (!target) return;
    if (target === session.username) {
      setError("You can't message yourself.");
      return;
    }

    setError('');
    setLoading(true);
    try {
      const user = await getUser(session.token, target);
      const dm = await createOrGetDm(session.token, { with_user_id: user.user_id });

      // Pre-cache the target's device keys.
      try {
        const resolved = await resolveUserDevice(session.token, target);
        updateCaches({
          peerDhCache: { ...session.peerDhCache, [resolved.deviceId]: resolved.dhPublicB64 },
          peerUsernames: { ...session.peerUsernames, [user.user_id]: target },
          userDeviceCache: {
            ...session.userDeviceCache,
            [resolved.userId]: [resolved.deviceId, resolved.dhPublicB64],
          },
        });
      } catch { /* keys can be fetched lazily on first send */ }

      onOpened(dm.thread_id, target, user.user_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'User not found');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal title="New Direct Message" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-gray-400">
            Username
          </label>
          <input
            autoFocus
            type="text"
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="Enter a username"
            className="w-full rounded-lg bg-surface-700 px-4 py-2.5 text-sm text-white placeholder-gray-500 outline-none ring-1 ring-surface-500 focus:ring-brand-500"
          />
        </div>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
          <button type="submit" disabled={loading} className="btn-primary">
            {loading ? 'Opening…' : 'Open DM'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
