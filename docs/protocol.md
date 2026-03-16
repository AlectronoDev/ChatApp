# Encryption Protocol

This document describes the cryptographic primitives, key types, session
establishment flows, and message envelope formats used by this application.
The implementation in `crates/crypto_core` must match what is written here.
If the implementation diverges, update this document first via review.

---

## Cryptographic Primitives

| Purpose | Algorithm | Rationale |
|---|---|---|
| Signing (device identity, messages) | Ed25519 | Fast, small keys, well-audited |
| Key agreement (session establishment) | X25519 ECDH | Pairs with Ed25519; standard in Signal + MLS |
| Symmetric encryption | AES-256-GCM or ChaCha20-Poly1305 | Both are AEAD; ChaCha20 preferred where hardware AES acceleration is not guaranteed |
| Key derivation | HKDF-SHA-256 | Standard, composable |
| Hashing | SHA-256 / SHA-512 | General use; SHA-512 for anything needing collision resistance |
| Password hashing | Argon2id | Memory-hard, recommended by OWASP 2024+ |
| Random number generation | OS CSPRNG via `getrandom` | All key generation must use this |

Rust crates to use (all in `crates/crypto_core`):
- `ed25519-dalek` — Ed25519 signing
- `x25519-dalek` — X25519 key agreement
- `aes-gcm` or `chacha20poly1305` — AEAD
- `hkdf` + `sha2` — key derivation
- `argon2` — password hashing
- `rand` (backed by `getrandom`) — secure RNG

Do not use `ring` and `dalek` in the same crate for the same primitive; pick
one family and stay consistent to avoid confusion.

---

## Identity Model

### Account and devices

Each user account can have multiple registered devices (e.g. a browser session
and a desktop app). The server knows about devices but cannot impersonate them.

```
User Account
 ├── Device A  (laptop)
 │    ├── IdentityKey (Ed25519 signing keypair)       — long-lived
 │    ├── IdentityDHKey (X25519 keypair)              — long-lived, for X3DH
 │    ├── SignedPreKey (X25519 keypair, signed by IK)  — rotated periodically
 │    └── One-time PreKeys (X25519)                   — consumed per session
 └── Device B  (browser)
      └── (same structure)
```

### What the server stores per device

```json
{
  "device_id": "<uuid>",
  "user_id": "<uuid>",
  "identity_key": "<base64 Ed25519 public key>",
  "identity_dh_key": "<base64 X25519 public key>",
  "signed_prekey": {
    "key_id": 1,
    "public_key": "<base64 X25519 public key>",
    "signature": "<base64 Ed25519 signature over key_id + public_key>"
  },
  "one_time_prekeys": [
    { "key_id": 42, "public_key": "<base64>" },
    ...
  ]
}
```

The server never stores any private key material. It only stores enough public
material to allow a peer to initiate an encrypted session without the recipient
being online.

---

## Direct Messages: X3DH + Double Ratchet

DMs between two users follow the Signal Protocol's two-phase design.

### Phase 1: Session establishment (Extended Triple Diffie-Hellman — X3DH)

Performed once per new device-to-device DM session. The initiator fetches the
recipient's key bundle from the server and derives a shared root secret without
any real-time interaction.

```
Initiator (Alice, device Ai)               Server              Recipient (Bob, device Bj)
     |                                       |                        |
     |  GET /keys/user/{bob}/devices/{Bj}    |                        |
     |──────────────────────────────────────>|                        |
     |<── { IK_B, IK_DH_B, SPK_B, OPK_B } ──|                        |
     |                                       |                        |
     | Generate ephemeral keypair EK_A                               |
     |                                       |                        |
     | DH1 = DH(IK_A_dh, SPK_B)                                     |
     | DH2 = DH(EK_A,    IK_DH_B)                                   |
     | DH3 = DH(EK_A,    SPK_B)                                     |
     | DH4 = DH(EK_A,    OPK_B)   (if OPK present)                 |
     | SK   = HKDF(DH1 || DH2 || DH3 [|| DH4])                     |
     |                                       |                        |
     | Initial message includes { IK_A, EK_A, OPK_key_id_used }    |
     |──────────────────────────────────────>|                        |
     |                                       |──── deliver ──────────>|
     |                                       |               Bob derives SK
     |                                       |               same 4 DH ops
```

After both sides derive `SK`, they initialize a Double Ratchet session from it.

### Phase 2: Ongoing messaging (Double Ratchet)

Each message advances the ratchet. An attacker who obtains a session key for
message N cannot derive keys for message N-1 (forward secrecy) and, after
further ratchet advances, also cannot trivially derive keys for N+1
(limited break-in recovery).

The Double Ratchet is not reimplemented from scratch. Use a well-audited
library (`double-ratchet` crate or the signal-protocol bindings) or implement
it strictly per the [Signal spec](https://signal.org/docs/specifications/doubleratchet/).

### Multi-device fanout for DMs

A DM message is encrypted independently for each of the recipient's registered
devices. The sender also encrypts a copy for each of their own other devices so
those devices can display the sent message.

```
Alice (device Ai) sends to Bob (who has Bj and Bk):
  → Encrypt payload for Bj  (X3DH/DR session Ai→Bj)
  → Encrypt payload for Bk  (X3DH/DR session Ai→Bk)
  → Encrypt payload for Ai's other devices (so they show the sent message)
  → POST /messages  { envelopes: [{ device_id: Bj, ciphertext }, ...] }
```

The server stores these envelopes and delivers them. It cannot read any of them.

---

## Server/Channel Messages: Messaging Layer Security (MLS)

Server channels have dynamic membership — users join and leave. Maintaining
pairwise X3DH sessions for every pair of members does not scale, and more
importantly it does not provide post-compromise security across membership
changes. MLS (RFC 9420) solves both problems.

### Overview

MLS organizes group members in a binary tree (ratchet tree). Each leaf is a
device. The root of the tree represents a shared group secret called the
**epoch secret**. When any member is added or removed, the tree is updated and
a new epoch secret is derived that the removed member cannot compute.

Key properties:
- **Forward secrecy**: old epoch secrets are deleted after advancing.
- **Post-compromise security**: a removed member cannot compute the new epoch
  secret even if they had the previous one.
- **Scalability**: key material is O(log N) per membership change, not O(N²).

### MLS in Rust

Use the [`openmls`](https://github.com/openmls/openmls) crate, which implements
RFC 9420. It is the primary production-grade MLS library in Rust.

`openmls` belongs in `crates/crypto_core` as the group session management
dependency. The API service is never given access to the MLS epoch secrets —
it only receives serialized MLS messages (proposals, commits, application
messages) which it validates structurally and routes/stores as opaque blobs.

### Key concepts mapped to this app

| MLS term | App term |
|---|---|
| Group | Channel (or DM thread) |
| Member | Device enrolled in a channel |
| KeyPackage | Per-device credential published to the server |
| Proposal | Membership change proposal (add/remove/update) |
| Commit | Finalized epoch advance applying a set of proposals |
| Welcome message | Encrypted message sent to a newly added device so it can join the group |
| Application message | An actual encrypted chat message |
| Epoch | A versioned group state; changes on every commit |

### Channel message flow

```
Alice commits an Add for a new member → server distributes Commit + Welcome
All existing devices process Commit   → advance to new epoch, derive new epoch secret
New device processes Welcome          → joins directly at the current epoch

Alice sends a message:
  → client calls openmls::group::create_message(plaintext)
  → openmls returns an MLS ApplicationMessage (ciphertext)
  → POST /channels/{id}/messages  { mls_ciphertext: <blob> }
  → server stores blob, fans out to all members
  → each recipient device calls openmls::group::process_message(blob)
  → openmls returns plaintext
```

### Server role in MLS

The server acts as a **Delivery Service** (DS) in MLS terminology:
- Stores and distributes KeyPackages.
- Orders and stores Commit messages so all devices see the same transcript.
- Fans out encrypted application messages.
- Does not participate in any key derivation.

The server should validate that MLS messages are well-formed (correct framing,
valid group ID, etc.) but must not attempt to decrypt them.

---

## Message Envelope Format

All messages stored by the server conform to the following envelope, regardless
of whether they are DM (Double Ratchet) or channel (MLS) messages.

```
MessageEnvelope {
    id:              UUID v7          // server-assigned, monotonically ordered
    conversation_id: UUID             // DM thread or channel ID
    sender_device_id: UUID
    sent_at:         RFC 3339 timestamp (server-assigned, untrusted for ordering)
    protocol:        "DR" | "MLS"
    ciphertext:      bytes            // opaque to the server
    recipient_device_id: UUID | null  // set for DR (per-device), null for MLS (broadcast)
}
```

The server may index on `id`, `conversation_id`, `sender_device_id`, and
`sent_at` for routing and pagination. It must not index on or attempt to parse
`ciphertext`.

---

## Account Recovery

No email address is collected or stored. Account recovery therefore works
entirely through two mechanisms:

### Recovery code (password reset path)

At signup, the server generates a cryptographically random 128-bit recovery
code, presents it to the user **once** as a formatted token (e.g.
`XXXX-XXXX-XXXX-XXXX-XXXX`), and stores only its Argon2id hash server-side.
The user is responsible for saving this code securely (e.g. a password manager
or printed copy).

To reset a forgotten password:
1. User submits their username + recovery code.
2. Server verifies the recovery code hash, then allows the user to set a new
   password and receive a new session.
3. The recovery code is immediately invalidated after use (single-use).
4. A new recovery code is generated and shown once.

**The recovery code resets the server-side credential only.** It does not
give the new session access to ciphertext encrypted to previously registered
device keys. Encrypted message history from old devices is permanently
inaccessible without those device keys.

### Multi-device redundancy (preferred path)

The best protection against losing account access is registering more than one
device. As long as any registered device remains accessible, the user can:
- Authenticate without needing the recovery code.
- Re-establish sessions on new devices from a trusted existing device.
- Retain access to their encrypted message history.

### Explicit limitations

- No email fallback. If a user loses all devices **and** their recovery code,
  the account cannot be recovered. It is permanently inaccessible.
- Even a successful recovery-code reset cannot decrypt history from lost
  devices.
- A future hardening feature may allow exporting an encrypted key backup
  secured by a user-chosen passphrase, stored locally or in user-controlled
  cloud storage. This would never be stored in plaintext on the server.

These limitations must be communicated clearly in the UI at signup.

---

## Key Rotation Schedule

| Key type | Rotation trigger |
|---|---|
| One-time prekeys | Consumed on first use; replenished automatically when count falls low |
| Signed prekey | Rotated every 30–90 days or on device re-registration |
| Long-term identity key | Only on explicit device reset or compromise recovery |
| MLS leaf key | On every MLS Update proposal (periodic or post-compromise) |
| DM ratchet state | Advances with every message automatically |

---

## What Is NOT Encrypted

The following metadata travels in plaintext (to the server and any network
observer after TLS terminates at the server):

- Account IDs and device IDs
- Conversation (thread/channel) IDs and membership lists
- Message timestamps
- Read receipts and delivery acknowledgements
- Approximate message sizes
- Typing indicators (if implemented)
- Server/channel names and descriptions

This is documented here so the team makes conscious decisions when adding new
fields rather than inadvertently leaking sensitive data.
