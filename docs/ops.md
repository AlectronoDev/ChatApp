# Operations and Security Guide

This document covers how to operate the backend without silently violating the
E2EE threat model. It is intended for anyone deploying, monitoring, or
responding to incidents on this system.

---

## 1. What Is and Isn't Logged

### 1.1 Structured audit events (`audit.rs`)

Every security-sensitive operation emits a structured log event with a
dot-namespaced `event` field (e.g. `auth.login.success`). These events are
safe to ship to a SIEM or log aggregator. Fields present in audit events:

| Field | Description |
|---|---|
| `event` | Dot-namespaced event name (always present) |
| `user_id` | UUID of the affected user (non-secret) |
| `device_id` | UUID of the affected device (non-secret) |
| `username` | Account username (public identifier) |
| `session_id` | UUID of the session being revoked (non-secret) |
| `reason` | Generic failure category (e.g. `bad_credentials`) |
| `epoch` | MLS epoch numbers (structural, non-secret) |
| `member_count` | Group member count (structural, non-secret) |

### 1.2 What MUST NEVER appear in logs

The logging infrastructure is designed to never emit the following. If any of
these appear in log output, treat it as a **critical bug**:

- **Passwords** (raw or hashed)
- **Session tokens** (raw or SHA-256 hashed)
- **Recovery codes** (raw or SHA-256 hashed)
- **Private cryptographic key material** (X25519 scalars, Ed25519 signing keys,
  MLS init key private halves)
- **Message plaintext** (any decrypted application content)
- **AEAD nonces** (would assist in nonce-reuse attacks if exposed)
- **Full Argon2 hashes** (timing attacks if compared in non-constant time)

### 1.3 Request tracing (`middleware.rs`)

The `trace_requests` middleware emits one log line per HTTP request containing:
`request_id`, `method`, `path` (no query string), `status`, `latency_ms`.

Query strings are intentionally excluded because they may contain cursor values,
search terms, or UUIDs that could leak structural information.

**Headers not logged**: `Authorization`, `Cookie`, or any other header.
**Bodies not logged**: neither request nor response bodies.

---

## 2. Deployment Checklist

Work through this list before every non-local deployment.

### 2.1 Required environment variables

| Variable | Description | Required? |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | **Required** |
| `REQUIRE_HTTPS=true` | Enables HSTS header; see §2.2 | **Required in prod** |
| `SESSION_DURATION_DAYS` | Session token lifetime (default: 30) | Optional |
| `KEY_BUNDLE_RATE_LIMIT_RPS` | X3DH key bundle fetches/user/sec (default: 2) | Optional |
| `AUTH_RATE_LIMIT_RPS` | Auth endpoint attempts/username/sec (default: 1) | Optional |
| `LOG_FORMAT=json` | Machine-parseable log output | Recommended in prod |
| `RUST_LOG=info` | Minimum log level | Recommended |

### 2.2 HTTPS enforcement

**Always terminate TLS at the edge** (reverse proxy, load balancer, or CDN).
The API server binds to plain HTTP (port 3000); TLS must be provided by the
deployment layer.

Set `REQUIRE_HTTPS=true` in all non-local environments. This:
1. Adds `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
   to every response (2-year HSTS pin).
2. Prevents accidental plain-HTTP deployment — a startup warning is logged if
   this flag is `false`.

If `REQUIRE_HTTPS` is left unset, the server logs at startup:

```
WARN: REQUIRE_HTTPS is disabled — HSTS will not be sent. Set REQUIRE_HTTPS=true
in all non-local deployments.
```

### 2.3 Secret management

Never commit secrets to version control. Use a secrets manager (Vault, AWS
Secrets Manager, Doppler) or environment injection at deploy time.

Secrets in this system:
- `DATABASE_URL` — contains DB credentials; rotate via DB credential rotation
- Session tokens — never stored; only SHA-256 hashes are persisted
- Recovery codes — never stored; only SHA-256 hashes are persisted

### 2.4 Database hardening

- The database user for this service needs only `SELECT`, `INSERT`, `UPDATE`,
  `DELETE` on application tables. It must NOT have `SUPERUSER`, `CREATEDB`, or
  DDL privileges (migrations run separately).
- Enable PostgreSQL connection encryption (`sslmode=require` in `DATABASE_URL`).
- Enable row-level logging in PostgreSQL audit extensions (pgaudit) if your
  compliance requirements mandate it. This is separate from application-level
  audit events and captures DB-level access.
- Back up the database regularly (see §4).

### 2.5 Rate limiting

Rate limits are in-process (DashMap-backed GCRA). In multi-instance deployments,
each instance maintains its own quota, effectively multiplying the limit by the
instance count. Migrate to a shared rate-limiting layer (Redis + a leaky-bucket
implementation) before scaling beyond a single instance.

---

## 3. Backup and Restore Policy

### 3.1 What CAN be safely backed up

The following database tables can be backed up and restored without violating
the E2EE threat model (the server holds no plaintext or private keys):

| Table | Contents | Safe to back up |
|---|---|---|
| `users` | Username, password_hash, recovery_code_hash | Yes |
| `sessions` | token_hash, expiry | Yes (tokens rotate anyway) |
| `devices` | Public identity keys, signed prekeys | Yes (all public) |
| `device_one_time_prekeys` | Public OTPK material | Yes (all public) |
| `message_envelopes` | **Per-device ciphertext** | Yes — opaque blobs |
| `channel_envelopes` | **Per-device ciphertext** | Yes — opaque blobs |
| `ratchet_sessions` | **Client-encrypted state blob** | Yes — opaque |
| `mls_groups` / `mls_group_members` | Group metadata | Yes |
| `mls_messages` | **Group ciphertext** | Yes — opaque blobs |
| `mls_key_packages` | Public KeyPackage material | Yes (all public) |
| `mls_welcome_messages` | **Encrypted to recipient** | Yes — opaque blobs |

### 3.2 Why backups don't break E2EE

The server stores only:
- Public key material (verifiable by anyone)
- Ciphertext blobs (encrypted client-side; the server cannot decrypt them)
- Hashes of secrets (SHA-256 of tokens, Argon2id of passwords)

A database backup does NOT restore message history to the server — it restores
the same opaque ciphertext blobs. Only clients with the correct private keys can
decrypt them.

### 3.3 What MUST NOT be backed up in unencrypted form

Private key material **never enters the database by design**. If you ever see
64-byte Ed25519 signing key scalars or 32-byte X25519 private scalars in the
database, that is a critical bug — do not back up the export and investigate
immediately.

### 3.4 Restore procedure

1. Restore database to a point-in-time snapshot.
2. Run migrations (`cargo sqlx migrate run`) if restoring to an older schema.
3. Active sessions in the restored snapshot that were issued after the snapshot
   timestamp will be invalid. Users will be prompted to log in again.
4. MLS group state after the snapshot is consistent with what was in the DB
   at snapshot time — clients will re-sync by fetching new messages.

---

## 4. Incident Response Playbooks

### 4.1 Compromised device key

**Scenario**: A device's private identity key (Ed25519 or X25519) was leaked
(e.g. device stolen, malware, key material exfiltrated).

**What the server knows**: The compromised device's UUID and its public keys
(already public, so no new information is exposed by a DB breach).

**What is at risk**: All future DM sessions established via X3DH with that
device, and future MLS messages the device receives.

**Response steps**:
1. The user must delete the compromised device via `DELETE /devices/{id}`.
   This cascades to prekeys and session state, preventing new X3DH initiations.
2. For MLS channels the device was a member of: any group member must submit a
   Commit with a Remove proposal for the compromised device. This advances the
   epoch and re-derives all encryption keys, cutting the device out of all
   future traffic.
3. Double Ratchet sessions with the device: the server cannot force these to
   end, but once the Double Ratchet advances past the compromised device's last
   known state, forward secrecy is restored. All peers should initiate new
   X3DH sessions.
4. The user should rotate their account credentials (password + recovery code)
   in case the device breach also exposed those.

**Forward secrecy note**: Messages sent and received BEFORE the device was
compromised are protected by Double Ratchet forward secrecy. An attacker with
only the current private key cannot decrypt past messages (assuming the ratchet
state was not exfiltrated).

### 4.2 Compromised account credentials

**Scenario**: A user's password or recovery code was compromised.

**Response steps**:
1. If recovery code is still valid: call `POST /auth/recover` with the recovery
   code. This atomically:
   - Rotates the password to the new value.
   - Rotates the recovery code (old one is immediately invalidated).
   - Revokes ALL existing sessions (including any attacker sessions).
2. If the recovery code is also compromised: the account cannot be automatically
   recovered. An administrator must directly update `users.password_hash` and
   `users.recovery_code_hash` in the database after verifying the user's
   identity through an out-of-band process.
3. The user should verify all registered devices and remove any unrecognized
   ones (`GET /devices`, `DELETE /devices/{id}`).
4. Advise the user that message history from before the compromise is protected
   by Double Ratchet forward secrecy on the device side; account credential
   compromise alone does not decrypt stored ciphertext.

### 4.3 Compromised server / database breach

**Scenario**: An attacker gains read (or read/write) access to the database or
server process.

**What the attacker gains from read access**:
- Usernames, account creation times, session token hashes
- Public key material (already public by design)
- Ciphertext blobs (cannot be decrypted without client private keys)
- Argon2id password hashes (computationally expensive to crack; see §4.3.1)
- SHA-256 hashes of session tokens (must be brute-forced if tokens are short)

**What the attacker does NOT gain**:
- Private key material (never stored)
- Message plaintext (encrypted client-side)
- Session tokens (raw tokens never stored)

**Response steps**:
1. **Immediately rotate all database credentials** and restart the service with
   the new `DATABASE_URL`.
2. **Revoke all active sessions** by running:
   ```sql
   UPDATE sessions SET revoked_at = NOW() WHERE revoked_at IS NULL;
   ```
   This forces all users to log in again.
3. Notify users that the database was compromised and advise them to:
   - Change their passwords immediately.
   - Rotate their recovery codes (via recover endpoint).
   - Treat all stored ciphertext as potentially linkable to the attacker
     (metadata leak — who talked to whom, when, approximate message sizes).
4. **Audit write-access breaches separately**: if the attacker had write access
   they could have replaced public key material (public keys in `devices` table)
   with their own, performing a key-substitution attack for future sessions.
   All users should verify their key fingerprints against a trusted reference.
   Existing Double Ratchet and MLS sessions are unaffected (they were
   established before the compromise).

#### 4.3.1 Password hash strength

Passwords are hashed with Argon2id (m=19 MiB, t=2, p=1). A brute-force attack
on the Argon2id hashes requires ~19 MiB RAM and ~2 hash evaluations per guess.
On commodity hardware this is ~10–50 ms per guess. An attacker cracking 100
hashes in parallel at 50 ms/guess would need 50 ms per password attempt — still
orders of magnitude slower than bcrypt for a typical attack rig. Passwords
shorter than 12 characters with low entropy remain guessable given sufficient
time. Advise users to use a password manager.

---

## 5. Key Audit Events Reference

Use these event names in SIEM alert rules and anomaly detectors.

| Event | Level | Meaning |
|---|---|---|
| `auth.signup` | INFO | New account created |
| `auth.rate_limited` | WARN | Auth endpoint throttled (brute-force indicator) |
| `auth.login.success` | INFO | Login succeeded |
| `auth.login.failure` | WARN | Login failed (wrong credentials) |
| `auth.login.session_cap` | WARN | Login rejected: max sessions reached |
| `auth.logout` | INFO | Session revoked |
| `auth.recover.success` | INFO | Account recovered via recovery code |
| `auth.recover.failure` | WARN | Recovery failed (wrong code — brute-force indicator) |
| `device.registered` | INFO | New device added to account |
| `device.deleted` | INFO | Device removed from account |
| `keys.bundle_fetched` | INFO | X3DH/MLS key bundle served to requester |
| `keys.bundle_rate_limited` | WARN | Key bundle fetch throttled (scraping indicator) |
| `mls.group.initialized` | INFO | MLS group created for a channel |
| `mls.commit.accepted` | INFO | MLS Commit accepted; epoch advanced |
| `mls.commit.rejected` | WARN | MLS Commit rejected (stale epoch, non-member) |

**Recommended alert thresholds**:
- `auth.login.failure` > 5 per username in 60 seconds → alert (brute force)
- `auth.rate_limited` > 50 per minute total → alert (distributed attack)
- `keys.bundle_rate_limited` > 10 per minute → alert (scraping)
- `auth.recover.failure` > 3 per username in 60 minutes → alert (recovery code guessing)
- `mls.commit.rejected` with reason `stale_epoch` spike → investigate (possible group split)
