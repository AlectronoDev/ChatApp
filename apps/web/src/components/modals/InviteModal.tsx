import { useState } from 'react';
import { useRequiredSession } from '../../context/SessionContext';
import { getUser, inviteToServer } from '../../api';
import Modal from './Modal';

interface Props {
  serverId: string;
  onClose: () => void;
}

export default function InviteModal({ serverId, onClose }: Props) {
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const session = useRequiredSession();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const target = username.trim();
    if (!target) return;

    setError('');
    setSuccess('');
    setLoading(true);
    try {
      const user = await getUser(session.token, target);
      await inviteToServer(session.token, serverId, { user_id: user.user_id });
      setSuccess(`${target} has been invited!`);
      setUsername('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invite failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal title="Invite to Server" onClose={onClose}>
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
        {success && <p className="text-sm text-green-400">{success}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="btn-secondary">Done</button>
          <button type="submit" disabled={loading || !username.trim()} className="btn-primary">
            {loading ? 'Inviting…' : 'Invite'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
