# Encryption Protocol

This document describes the cryptographic primitives, key types, session
establishment flows, and message envelope formats used by this application.
The implementation in `crates/crypto_core` must match what is written here.
If the implementation diverges, update this document first via review.

---

## Cryptographic Primitives


| Purpose                               | Algorithm                 | Rationale                                                                                         |
| ------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------- |
| Signing (device identity, messages)   | Ed25519                   | Fast, small keys, well-audited                                                                    |
| Key agreement (session establishment) | X25519 ECDH               | Pairs with Ed25519; standard in Signal + MLS                                                      |
| Symmetric encryption                  | ChaCha20-Poly1305         | Canonical AEAD cipher for all message encryption. AES-256-GCM is not used in this implementation. |
| Key derivation                        | HKDF-SHA-256              | Standard, composable                                                                              |
| Hashing                               | SHA-256 / SHA-512         | General use; SHA-512 for anything needing collision resistance                                    |
| Password hashing                      | Argon2id                  | Memory-hard, recommended by OWASP 2024+                                                           |
| Random number generation              | OS CSPRNG via `getrandom` | All key generation must use this                                                                  |


Rust crates to use (all in `crates/crypto_core`):

- `ed25519-dalek` — Ed25519 signing
- `x25519-dalek` — X25519 key agreement
- `chacha20poly1305` — AEAD (`aes-gcm` is not used)
- `hkdf` + `sha2` — key derivation
- `argon2` — password hashing
- `rand` (backed by `getrandom`) — secure RNG

Do not use `ring` and `dalek` in the same crate for the same primitive; pick
one family and stay consistent to avoid confusion.

> **Legacy note:** `crates/crypto_core/src/lib.rs` also contains a simplified
> static-ECDH session model (`ecdh_session_key`, `encrypt_for_device`,
> `decrypt_from_device`). That code is **non-production**; it lacks forward
> secrecy and is retained for reference only. It must not be used in live DM
> paths. All production DM encryption goes through X3DH + Double Ratchet.

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
    "signature": "<base64 Ed25519 signature over (key_id_be32 ‖ public_key_bytes)>"
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

**Signed prekey signature encoding:** The Ed25519 signature covers the exact
byte sequence `key_id_be32 ‖ public_key_bytes`, where `key_id_be32` is the
4-byte big-endian encoding of the integer key ID and `public_key_bytes` is the
raw 32-byte X25519 public key. The resulting 64-byte signature is base64-encoded
for storage and transmission. The server verifies this signature on registration.

**One-time prekey minimum:** At least **10** one-time prekeys must be uploaded
at device registration. Clients should upload 50–100 keys initially so fresh
per-session material is available for many concurrent session initiations before
a replenishment upload is needed.

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
     | SK  = KDF_X3DH(DH1, DH2, DH3 [, DH4])                       |
     |                                       |                        |
     | Initial message includes X3dhInitMessage + first DR envelope  |
     |──────────────────────────────────────>|                        |
     |                                       |──── deliver ──────────>|
     |                                       |               Bob derives SK
     |                                       |               same 4 DH ops
```

#### Exact X3DH KDF

```
IKM = (0xFF × 32) ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4]   // 128 or 160 bytes
SK  = HKDF-SHA256(
        salt = 0x00 × 32,
        ikm  = IKM,
        info = "chat-x3dh-v1"
      )  →  32 bytes
```

The leading `0xFF × 32` (called `F` in the X3DH spec) prevents a degenerate
all-zero `SK` and is required by the specification regardless of whether DH4 is
included.

#### X3DH bootstrap message format

The initiator transmits the following alongside the first Double Ratchet message.
The responder uses these fields to reproduce the DH computations and derive `SK`.

```
X3dhInitMessage {
  ik_dh_pub : [u8; 32]       // initiator's X25519 identity DH public key (for DH2)
  ek_pub    : [u8; 32]       // initiator's ephemeral X25519 public key (for DH2/DH3/DH4)
  spk_id    : i32             // responder's signed prekey ID that was used
  otpk_id   : Option<i32>    // responder's one-time prekey ID used, if any
}
```

The `X3dhInitMessage` is sent with the very first ratchet message of a new session.
Subsequent messages do not include it.

After both sides derive `SK`, they initialize a Double Ratchet session from it.

### Phase 2: Ongoing messaging (Double Ratchet)

Each message advances the ratchet. An attacker who obtains a session key for
message N cannot derive keys for message N-1 (forward secrecy) and, after
further ratchet advances, also cannot trivially derive keys for N+1
(break-in recovery).

The Double Ratchet is implemented from scratch in
`crates/crypto_core/src/double_ratchet.rs` following the
[Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
exactly. The implementation is authoritative; this section documents what it
does so that any reimplementation produces identical outputs.

#### KDF functions

```
KDF_RK(rk, dh_out):
  HKDF-SHA256(salt=rk, ikm=dh_out, info="chat-dr-ratchet-v1") → 64 bytes
  new_rk = output[0..32]
  ck     = output[32..64]

KDF_CK(ck):
  mk     = HMAC-SHA256(key=ck, data=0x01)   → 32 bytes  (message key)
  new_ck = HMAC-SHA256(key=ck, data=0x02)   → 32 bytes  (next chain key)

msg_keys(mk):
  HKDF-SHA256(salt=0x00×32, ikm=mk, info="chat-dr-msg-v1") → 44 bytes
  cipher_key = output[0..32]    (ChaCha20-Poly1305 32-byte key)
  nonce      = output[32..44]   (ChaCha20-Poly1305 12-byte nonce)
```

The `0x01`/`0x02` domain-separation bytes in KDF_CK match the Signal spec
exactly. The nonce is derived deterministically — since each `mk` is
single-use, there is no nonce-reuse risk.

#### Message header and AAD encoding

Every ratchet message carries a plaintext header that is bound to the ciphertext
as AEAD additional authenticated data (AAD). Tampering with any header field
causes decryption to fail.

```
MessageHeader {
  dh_pub : [u8; 32]   // sender's current X25519 ratchet public key
  pn     : u32        // length of sender's previous send chain
  n      : u32        // index of this message in the current send chain (0-based)
}

Header wire encoding (40 bytes, deterministic, used as AEAD AAD):
  encode(header) = dh_pub[32] ‖ pn.to_be_bytes()[4] ‖ n.to_be_bytes()[4]
```

#### Message encryption

```
RatchetMessage {
  header    : MessageHeader      // transmitted in plaintext
  ciphertext: Vec<u8>            // plaintext length + 16-byte AEAD auth tag
}

Encryption:
  (new_cks, mk) = KDF_CK(cks)
  (cipher_key, nonce) = msg_keys(mk)
  ciphertext = ChaCha20-Poly1305(
    key   = cipher_key,
    nonce = nonce,
    aad   = encode(header)
  ).encrypt(plaintext)
```

#### Session initialization

**Initiator (Alice), called after X3DH:**

```
Alice.dhs         = generate_dh_keypair()           // fresh X25519 ratchet key pair
Alice.dhr         = Bob's SPK_B public key           // Bob's signed prekey is the first ratchet key
Alice.rk, Alice.cks = KDF_RK(SK, DH(Alice.dhs, Alice.dhr))
Alice.ckr         = None
Alice.ns = Alice.nr = Alice.pn = 0
Alice.skipped     = {}
```

Alice has a send chain key and can encrypt immediately.

**Responder (Bob), called after X3DH:**

```
Bob.dhs           = (SPK_B_secret, SPK_B_public)    // signed prekey is Bob's first ratchet key pair
Bob.dhr           = None
Bob.rk            = SK
Bob.cks = Bob.ckr = None
Bob.ns = Bob.nr = Bob.pn = 0
Bob.skipped       = {}
```

Bob cannot send until he receives Alice's first message, which triggers his
first DH ratchet step and generates `cks`.

#### Out-of-order messages and skipped-key cache

When a receiver encounters a message with counter `n` ahead of its current
`nr`, it advances the chain key, caches unused message keys indexed by
`(sender_ratchet_pub, message_n)`, and then decrypts the received message.
Cached keys are consumed and deleted on first use.

**Maximum skipped keys per session: 1000.** If a sender's `n` would require
caching more than 1000 keys, `decrypt` returns `TooManySkippedMessages` and
the receive call fails without modifying session state.

#### Session persistence format (v1)

Sessions are serialized as versioned JSON. All `[u8; 32]` arrays are
base64-encoded using standard alphabet with padding. The `version` field
allows future incompatible changes to be detected and rejected cleanly.

```json
{
  "version"    : 1,
  "dhs_secret" : "<base64 32-byte X25519 secret>",
  "dhs_public" : "<base64 32-byte X25519 public>",
  "dhr"        : "<base64 32-byte X25519 public>",
  "rk"         : "<base64 32-byte root key>",
  "cks"        : "<base64 32-byte send chain key>",
  "ckr"        : "<base64 32-byte recv chain key>",
  "ns"         : 0,
  "nr"         : 0,
  "pn"         : 0,
  "skipped"    : [
    { "dh_pub": "<base64>", "n": 0, "mk": "<base64>" }
  ]
}
```

Fields that are `None` in the live session are omitted from JSON. `dhs_secret`
and `dhs_public` must both be present or both absent; a mismatch is a
deserialization error. The current session version is **1**; any other value
must be rejected.

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

Use the `[openmls](https://github.com/openmls/openmls)` crate, which implements
RFC 9420. It is the primary production-grade MLS library in Rust.

`openmls` belongs in `crates/crypto_core` as the group session management
dependency. The API service is never given access to the MLS epoch secrets —
it only receives serialized MLS messages (proposals, commits, application
messages) which it validates structurally and routes/stores as opaque blobs.

### Key concepts mapped to this app


| MLS term            | App term                                                                |
| ------------------- | ----------------------------------------------------------------------- |
| Group               | Channel (or DM thread)                                                  |
| Member              | Device enrolled in a channel                                            |
| KeyPackage          | Per-device credential published to the server                           |
| Proposal            | Membership change proposal (add/remove/update)                          |
| Commit              | Finalized epoch advance applying a set of proposals                     |
| Welcome message     | Encrypted message sent to a newly added device so it can join the group |
| Application message | An actual encrypted chat message                                        |
| Epoch               | A versioned group state; changes on every commit                        |


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


| Key type               | Rotation trigger                                                      |
| ---------------------- | --------------------------------------------------------------------- |
| One-time prekeys       | Consumed on first use; replenished automatically when count falls low |
| Signed prekey          | Rotated every 30–90 days or on device re-registration                 |
| Long-term identity key | Only on explicit device reset or compromise recovery                  |
| MLS leaf key           | On every MLS Update proposal (periodic or post-compromise)            |
| DM ratchet state       | Advances with every message automatically                             |


---

## Ratchet State Persistence Contract

This section documents the invariants the server guarantees and the procedure
clients **must** follow to keep Double Ratchet session state consistent across
retries, crashes, and concurrent device instances.

### Server guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| **Idempotent message submission** | Clients supply a client-generated UUID v7 `batch_id` in every send request. The server returns the original response without inserting duplicate envelopes if it has already accepted that `batch_id` from the same sender in the same thread/channel. |
| **All-or-nothing envelope batch** | All envelopes in one send are inserted inside a single database transaction. A crash mid-insert rolls back to zero rows — no partial batches are visible to recipients. |
| **Encrypted session state backup** | `PUT /devices/{my}/ratchet-sessions/{peer}` accepts an opaque client-encrypted blob and stores it server-side with an optimistic-lock version counter. The server cannot read, validate, or transform the blob. |
| **Version-safe state updates** | The PUT endpoint requires the client to supply the last-read `expected_version`. If a concurrent write occurred since the last read, the server returns **409 Conflict**; the client must re-read and retry. |
| **Cascade cleanup** | When a device is deleted, all its session state records are deleted via `ON DELETE CASCADE`. |

### Correct send procedure (atomic crash recovery)

```
1.  Generate a fresh UUID v7  →  batch_id
2.  Read current ratchet state version from server (or use in-memory state)
3.  Advance ratchet → encrypt plaintext → hold ciphertext in memory
4.  POST /dms/{thread}/messages  { batch_id, envelopes: [ciphertext] }
        • If network error or crash → retry step 4 with the SAME batch_id
        • The server de-duplicates; the retry is a no-op
5.  On HTTP 2xx → encrypt new RatchetSession state with device storage key
6.  PUT /devices/{my}/ratchet-sessions/{peer}  { expected_version, encrypted_state }
        • If 409 Conflict → another instance wrote concurrently
              → re-read, decide how to merge, retry step 6
        • If success → persist confirmed; done
```

If a crash occurs between steps 4 and 6:
- On recovery, retry step 4 with the same `batch_id` → server returns 200 idempotently.
- Proceed to step 6. The session state backup is updated to reflect the now-confirmed message.

### Why deterministic re-encryption is safe

The Double Ratchet KDF chain is deterministic: calling `encrypt()` from the
same session state with the same plaintext always produces the same ciphertext.
This means crash-and-retry (restore checkpoint → re-encrypt → re-submit) yields
a byte-for-bit identical envelope. The server's `batch_id` deduplication ensures
the recipient sees exactly one copy regardless of how many times the sender
retries. See `crash_recovery_produces_identical_ciphertext` in the test suite.

### Replay and state-restore attacks

A replayed ciphertext delivered to a restored session is rejected by the
ChaCha20-Poly1305 AEAD tag check: after the receive chain has advanced past a
given `n`, the message key for that `n` is either consumed or no longer
derivable from the current chain key. Attempting to decrypt with the wrong key
fails with `CryptoError::DecryptionFailed`. See `restore_then_replay_is_rejected`
in the test suite.

### Bounded skipped-key cache

`MAX_SKIP = 1000` limits how far ahead the receive chain can advance to
cache skipped-message keys. If more than 1000 consecutive messages are skipped,
`RatchetSession::decrypt` returns `CryptoError::TooManySkippedMessages`. This
is an application-level error; the client should alert the user that out-of-order
delivery has exceeded safe limits (likely an active attack or extreme delivery
failure) and offer a session reset.

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