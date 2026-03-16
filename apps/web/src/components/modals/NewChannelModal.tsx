import { useState } from 'react';
import { useRequiredSession } from '../../context/SessionContext';
import { createChannel } from '../../api';
import { useQueryClient } from '@tanstack/react-query';
import Modal from './Modal';

interface Props {
  serverId: string;
  onClose: () => void;
  onCreated: () => void;
}

export default function NewChannelModal({ serverId, onClose, onCreated }: Props) {
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const session = useRequiredSession();
  const queryClient = useQueryClient();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) return;

    setError('');
    setLoading(true);
    try {
      await createChannel(session.token, serverId, { name: trimmed });
      queryClient.invalidateQueries({ queryKey: ['channels', serverId] });
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create channel');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal title="Create Channel" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-gray-400">
            Channel Name
          </label>
          <div className="flex items-center rounded-lg bg-surface-700 ring-1 ring-surface-500 focus-within:ring-brand-500">
            <span className="pl-3 text-gray-500">#</span>
            <input
              autoFocus
              type="text"
              value={name}
              onChange={e => setName(e.target.value.toLowerCase().replace(/\s+/g, '-'))}
              placeholder="general"
              maxLength={100}
              className="flex-1 bg-transparent px-2 py-2.5 text-sm text-white placeholder-gray-500 outline-none"
            />
          </div>
        </div>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
          <button type="submit" disabled={loading || !name.trim()} className="btn-primary">
            {loading ? 'Creating…' : 'Create Channel'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
