import { useState } from 'react';
import { useSession } from '../context/SessionContext';
import { signup, login, registerDevice } from '../api';
import { generateDeviceKeys } from '../crypto';
import { loadSession, type StoredSession } from '../storage';

type Tab = 'login' | 'signup';

export default function AuthPage() {
  const [tab, setTab] = useState<Tab>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState('');

  const { login: sessionLogin } = useSession();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      let userId: string;
      let token: string;
      let resolvedUsername: string;

      if (tab === 'signup') {
        const res = await signup({ username, password });
        userId = res.user_id;
        token = res.token;
        resolvedUsername = res.username;
        setRecoveryCode(res.recovery_code);
      } else {
        const res = await login({ username, password });
        userId = res.user_id;
        token = res.token;
        resolvedUsername = res.username;
      }

      // On login, reuse any existing device keys stored for this user so that
      // messages encrypted for that device remain decryptable. Only generate
      // and register new keys when there is no prior session (e.g. first login
      // on this browser, or the user explicitly cleared their data).
      const existing = loadSession();
      const canReuseDevice =
        tab === 'login' &&
        existing?.username === resolvedUsername &&
        existing.deviceId &&
        existing.dhSecretB64;

      let deviceId: string;
      let dhSecretB64: string;
      let peerDhCache = existing?.peerDhCache ?? {};
      let peerUsernames = existing?.peerUsernames ?? {};
      let userDeviceCache = existing?.userDeviceCache ?? {};

      if (canReuseDevice && existing) {
        deviceId = existing.deviceId;
        dhSecretB64 = existing.dhSecretB64;
      } else {
        const keys = generateDeviceKeys();
        const devRes = await registerDevice(token, {
          display_name: `${resolvedUsername}'s browser`,
          identity_key: keys.identityKeyB64,
          identity_dh_key: keys.dhPublicB64,
          signed_prekey: {
            key_id: keys.signedPrekeyId,
            public_key: keys.signedPrekeyPubB64,
            signature: keys.signedPrekeySigB64,
          },
          one_time_prekeys: [],
        });
        deviceId = devRes.device_id;
        dhSecretB64 = keys.dhSecretB64;
        // Fresh session — reset caches.
        peerDhCache = {};
        peerUsernames = {};
        userDeviceCache = {};
      }

      const session: StoredSession = {
        username: resolvedUsername,
        userId,
        token,
        deviceId,
        dhSecretB64,
        peerDhCache,
        peerUsernames,
        userDeviceCache,
      };

      sessionLogin(session);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-surface-900">
      <div className="w-full max-w-sm space-y-6 px-4">
        {/* Logo / title */}
        <div className="text-center">
          <div className="mx-auto mb-3 flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-500 text-2xl font-bold">
            C
          </div>
          <h1 className="text-2xl font-bold text-white">ChatApp</h1>
          <p className="mt-1 text-sm text-gray-400">End-to-end encrypted messaging</p>
        </div>

        {/* Tab switcher */}
        <div className="flex rounded-lg bg-surface-800 p-1">
          {(['login', 'signup'] as Tab[]).map(t => (
            <button
              key={t}
              onClick={() => { setTab(t); setError(''); setRecoveryCode(''); }}
              className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
                tab === t
                  ? 'bg-brand-500 text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {t === 'login' ? 'Log in' : 'Sign up'}
            </button>
          ))}
        </div>

        {/* Recovery code banner — shown once after signup */}
        {recoveryCode && (
          <div className="rounded-lg border border-yellow-500/40 bg-yellow-500/10 p-4 text-sm">
            <p className="font-semibold text-yellow-300">Save your recovery code!</p>
            <p className="mt-1 text-yellow-200/80">
              This is shown exactly once. If you lose your password, this is the only way to
              recover your account.
            </p>
            <code className="mt-2 block break-all rounded bg-surface-700 p-2 text-xs text-yellow-100">
              {recoveryCode}
            </code>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-gray-400">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              required
              autoComplete="username"
              className="w-full rounded-lg bg-surface-700 px-4 py-2.5 text-sm text-white placeholder-gray-500 outline-none ring-1 ring-surface-500 focus:ring-brand-500"
              placeholder="Enter your username"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-gray-400">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              autoComplete={tab === 'signup' ? 'new-password' : 'current-password'}
              className="w-full rounded-lg bg-surface-700 px-4 py-2.5 text-sm text-white placeholder-gray-500 outline-none ring-1 ring-surface-500 focus:ring-brand-500"
              placeholder="Enter your password"
            />
          </div>

          {error && (
            <p className="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-brand-500 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-brand-600 disabled:opacity-60"
          >
            {loading
              ? tab === 'signup'
                ? 'Creating account…'
                : 'Logging in…'
              : tab === 'signup'
              ? 'Create account'
              : 'Log in'}
          </button>
        </form>
      </div>
    </div>
  );
}
