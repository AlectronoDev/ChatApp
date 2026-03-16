# Threat Model

This document defines what the system protects, who the adversaries are, and
what security guarantees the design does and does not make. Every cryptographic
and architectural decision elsewhere in the codebase should trace back to a
claim made here.

---

## Assets

| Asset | Sensitivity | Notes |
|---|---|---|
| Message plaintext | Critical | The primary thing E2EE protects. Never stored or transmitted unencrypted through the server. |
| Device private keys | Critical | Loss or exposure completely breaks E2EE for that device. Stored only on the client device. |
| Account password | High | Used only to authenticate to the server and protect the account. Stored server-side as an Argon2id verifier — the server never sees the plaintext password after it is hashed. No email address is collected or stored. |
| Contact graph | Medium | The server necessarily knows which accounts have open DM threads and which accounts are in which servers. This is not hidden from the server. |
| Message metadata | Medium | Timestamps, sender account ID, approximate message size, and delivery receipts are visible to the server. |
| Public identity keys | Low-sensitivity | Intentionally public. The server stores and distributes these to enable session establishment. |

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│  Client device (trusted)                                    │
│  ┌──────────────┐   ┌────────────────────────────────────┐  │
│  │  Device keys │   │  Application / UI layer            │  │
│  │  (private)   │   │  Encrypt before sending;           │  │
│  └──────────────┘   │  decrypt after receiving.          │  │
│                     └────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────┘
                               │  TLS (transport layer only)
┌──────────────────────────────▼──────────────────────────────┐
│  Server (untrusted for content)                             │
│  • Stores ciphertext envelopes, never plaintext.            │
│  • Stores public key material for session bootstrap.        │
│  • Routes encrypted envelopes to recipient devices.         │
│  • Can observe metadata (who, when, how much).              │
└─────────────────────────────────────────────────────────────┘
```

---

## Adversary Model

### In-scope adversaries

**Adversary A: Malicious or compromised server operator**
The server operator — or an attacker who gains full access to the server and
database — must not be able to read message content. This is the primary
adversary the E2EE design defends against.

- The server sees: account identifiers, public keys, ciphertext blobs,
  timestamps, and delivery metadata.
- The server must not see: plaintext message bodies, plaintext attachment
  content, device private keys, or the symmetric session keys derived during
  DM/group session establishment.

**Adversary B: Passive network attacker**
A passive observer on the network between client and server must not be able to
read message content or meaningfully correlate traffic. TLS (at minimum TLS 1.3
via `rustls`) mitigates this at the transport layer. E2EE provides a second
independent layer.

**Adversary C: Compromised peer account (post-compromise)**
If a peer's device key is later compromised, the attacker must not be able to
decrypt messages sent before the compromise occurred. This is the **forward
secrecy** requirement and is addressed by the Double Ratchet used in DMs.

**Adversary D: Compromised peer account (future messages)**
After a device compromise is detected and that device is removed from a
group/DM session, that device must not be able to decrypt future messages.
This is the **break-in recovery** (post-compromise security) requirement and
is addressed by MLS epoch advances in server/channel messaging.

### Out-of-scope adversaries (for MVP)

- **Local device compromise**: If an attacker has physical access or code
  execution on the user's own device, local key storage is exposed. Secure
  local storage hardening is a hardening phase concern.
- **Traffic analysis / timing attacks**: The server can observe who communicates
  with whom and when, even without plaintext. Hiding the social graph requires
  additional mixing/padding which is out of scope.
- **Key impersonation without verification**: If a user does not verify a
  peer's key fingerprint out-of-band, a compromised server could substitute
  a different public key during initial session setup. Safety-number / key
  fingerprint display is a hardening phase item.

---

## Security Guarantees

| Guarantee | Mechanism |
|---|---|
| Message confidentiality against server | E2EE; server only stores ciphertext |
| Transport confidentiality | TLS 1.3 (rustls) |
| Message integrity and authenticity | Authenticated encryption (AEAD) + sender signing |
| Forward secrecy for DMs | Double Ratchet — each message advances ratchet state |
| Forward secrecy for group/channel messages | MLS epoch keys; old epoch keys are deleted after advancing |
| Break-in recovery for groups | MLS UpdatePath forces new key material that the removed device cannot derive |
| Password confidentiality at rest | Argon2id with a high cost parameter; only the verifier is stored |
| Multi-device isolation | Each device holds independent keypairs; compromise of one device does not expose another device's keys |

---

## Non-Guarantees (explicit)

- **Metadata privacy**: The server knows the social graph. Message timing and
  frequency are visible.
- **Full anonymity**: Accounts require only a chosen username and password — no
  email address, phone number, or personally identifying information is
  collected. However, the server still knows the IP addresses of connecting
  clients and the social graph (who communicates with whom).
- **Account recovery without a recovery code or device**: There is no email
  reset flow. If a user forgets their password and has neither a registered
  device nor their one-time recovery code, the account cannot be recovered.
  Even with a successful recovery-code reset, ciphertext encrypted to lost
  device keys remains permanently inaccessible. This is an inherent property
  of E2EE and must be documented to users clearly at signup.
- **Deniability**: Messages are authenticated with device keys, so recipients
  can prove authorship to a third party. Deniability via sender keys is a
  future consideration.

---

## Password Authentication vs. Cryptographic Identity

These are intentionally separate layers.

- **Password + session token**: Proves account ownership to the server.
  Controls access to the API (posting, fetching ciphertext envelopes, managing
  servers, etc.).
- **Device private key**: Controls the ability to decrypt messages. Stored
  only on the client. Never derived from or recoverable by the server.

A correct password gives an attacker an authenticated server session. It does
not give them the device private key and therefore does not let them decrypt
stored ciphertext. This separation is architecturally enforced by keeping all
decryption code in `crates/crypto_core` and never sending private key material
to the server.

---

## Key Revocation and Device Removal

- A user can remove a registered device from their account via an authenticated
  API call from another trusted device.
- Removing a device from a DM session or group/channel triggers key material
  rotation (MLS UpdatePath) so the removed device cannot decrypt future
  messages.
- The server enforces that key packages are only uploaded by the authenticated
  device owner.
