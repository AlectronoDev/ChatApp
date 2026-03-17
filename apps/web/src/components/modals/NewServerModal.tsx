import { useState } from 'react';
import { useRequiredSession } from '../../context/SessionContext';
import { createServer } from '../../api';
import Modal from './Modal';

interface Props {
  onClose: () => void;
  onCreated: () => void;
}

export default function NewServerModal({ onClose, onCreated }: Props) {
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const session = useRequiredSession();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) return;

    setError('');
    setLoading(true);
    try {
      await createServer(session.token, { name: trimmed });
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create server');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal title="Create Server" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-gray-400">
            Server Name
          </label>
          <input
            autoFocus
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="My Awesome Server"
            maxLength={100}
            className="w-full rounded-lg bg-surface-700 px-4 py-2.5 text-sm text-white placeholder-gray-500 outline-none ring-1 ring-surface-500 focus:ring-brand-500"
          />
        </div>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
          <button type="submit" disabled={loading || !name.trim()} className="btn-primary">
            {loading ? 'Creating…' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
