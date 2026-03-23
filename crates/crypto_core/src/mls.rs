//! MLS (Message Layer Security) support — server-side delivery service helpers.
//!
//! The server acts as a pure **Delivery Service (DS)** as defined in RFC 9420
//! §4. It stores and fans out opaque TLS-encoded MLS objects without
//! understanding their internal structure. The cryptographic state machine
//! (TreeKEM, epoch key schedule, ratchet tree) runs exclusively on client
//! devices.
//!
//! This module provides:
//! - Size bounds for all MLS object categories.
//! - A single opaque-blob validator (`validate_mls_blob`) used by API routes
//!   to reject malformed or oversized payloads before touching the database.
//! - Documentation stubs for the object types the DS relays, so future client
//!   implementations have a reference point for the expected wire format.

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::CryptoError;

// ─── Size bounds ──────────────────────────────────────────────────────────────
//
// All limits are on the base64-encoded string length (not the raw byte count).
// A base64-encoded N-byte payload is at most ceil(N/3)*4 + 4 characters.

/// Maximum size of a base64-encoded MLS KeyPackage.
///
/// A KeyPackage contains one Leaf Node (identity key, HPKE init key,
/// signature), protocol version, cipher suite, extensions, and a signature.
/// For typical cipher suites (X25519 + Ed25519 + AES-128-GCM-SHA256) a bare
/// KeyPackage is ~300–500 bytes; 8 KiB accommodates large extension sets.
pub const MAX_KEY_PACKAGE_B64_BYTES: usize = 10_924; // ceil(8192 / 3) * 4

/// Maximum size of a base64-encoded MLS Commit or Application message.
///
/// A Commit in a group of N members contains at most O(log₂ N) encrypted
/// path-update ciphertexts. For 1 000 members (~10 hops × ~200 bytes each),
/// a Commit is under 2 KiB; 64 KiB is generous headroom for large groups
/// with extension fields.
pub const MAX_MLS_MESSAGE_B64_BYTES: usize = 87_384; // ceil(65536 / 3) * 4

/// Maximum size of a base64-encoded MLS Welcome message.
///
/// A Welcome contains one GroupSecrets entry per new member (each ~200 bytes
/// encrypted with the recipient's HPKE init key) plus the GroupInfo block.
/// For batches of up to 100 new members: ~20 KiB; 64 KiB provides margin.
pub const MAX_WELCOME_B64_BYTES: usize = 87_384; // ceil(65536 / 3) * 4

/// Minimum number of KeyPackages a device must upload per request.
pub const MIN_KEY_PACKAGES_PER_UPLOAD: usize = 1;

/// Maximum number of KeyPackages a device may upload in a single request.
/// Prevents DB exhaustion attacks via bulk fake-key uploads.
pub const MAX_KEY_PACKAGES_PER_UPLOAD: usize = 100;

// ─── Validation ───────────────────────────────────────────────────────────────

/// Validate an opaque MLS object blob:
///   1. Must be non-empty.
///   2. Must not exceed `max_b64_bytes` (measured on the encoded string).
///   3. Must decode as valid standard base64 (no padding issues, valid chars).
///
/// The server does NOT parse the internal TLS structure — it is intentionally
/// opaque. Size and encoding checks are sufficient for the DS role.
pub fn validate_mls_blob(data: &str, max_b64_bytes: usize) -> Result<(), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::InvalidKeyLength); // reuse — represents "empty input"
    }
    if data.len() > max_b64_bytes {
        return Err(CryptoError::InvalidKeyLength);
    }
    // Verify the string is valid base64 (catches garbage/truncated uploads).
    B64.decode(data).map_err(CryptoError::Base64)?;
    Ok(())
}

// ─── MLS object type stubs (documentation only) ───────────────────────────────
//
// The following descriptions document the TLS-encoded structures the DS relays.
// They are NOT parsed by the server; they exist here so future client code
// written against this codebase has a reference for what to produce/consume.
//
// When a full MLS client library (e.g. `openmls`) is integrated, it will
// produce and consume these objects. The server's API accepts them as opaque
// base64 strings.
//
// MLS Cipher suite used by this deployment: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
//   (cipher suite 0x0001 per RFC 9420 §17.1 — mandatory-to-implement)
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  KeyPackage (RFC 9420 §10)                                              │
// │   version       ProtocolVersion  (MLS 1.0 = 1)                         │
// │   cipher_suite  CipherSuite      (0x0001)                               │
// │   init_key      HPKEPublicKey    (X25519, 32 bytes)                     │
// │   leaf_node     LeafNode         (identity, signing key, capabilities)  │
// │   extensions    Extension[]                                              │
// │   signature     opaque<V>        (over KeyPackageTBS, Ed25519)           │
// └─────────────────────────────────────────────────────────────────────────┘
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  MLSMessage (RFC 9420 §6)                                               │
// │   version      ProtocolVersion                                          │
// │   wire_format  WireFormat  (public_message | private_message | ...)     │
// │   payload      PublicMessage | PrivateMessage | Welcome | ...           │
// │                                                                         │
// │  Commit (inside PublicMessage/PrivateMessage, RFC 9420 §12.4):          │
// │   proposals    ProposalOrRef[]  (Add / Remove / Update proposals)       │
// │   path         UpdatePath?      (direct path with encrypted secrets)    │
// │                                                                         │
// │  Welcome (RFC 9420 §12.4.3.1):                                          │
// │   cipher_suite CipherSuite                                              │
// │   secrets      EncryptedGroupSecrets[]  (one per invited member)        │
// │   encrypted_group_info  opaque<V>                                       │
// └─────────────────────────────────────────────────────────────────────────┘

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_blob_passes_validation() {
        // A simple base64-encoded blob within size limits.
        let blob = base64::engine::general_purpose::STANDARD.encode(b"fake-key-package-data");
        assert!(validate_mls_blob(&blob, MAX_KEY_PACKAGE_B64_BYTES).is_ok());
    }

    #[test]
    fn empty_blob_is_rejected() {
        assert!(validate_mls_blob("", MAX_KEY_PACKAGE_B64_BYTES).is_err());
    }

    #[test]
    fn oversized_blob_is_rejected() {
        let big = "A".repeat(MAX_KEY_PACKAGE_B64_BYTES + 1);
        assert!(validate_mls_blob(&big, MAX_KEY_PACKAGE_B64_BYTES).is_err());
    }

    #[test]
    fn invalid_base64_is_rejected() {
        // `!` is not a valid base64 character.
        assert!(validate_mls_blob("not!!valid==", MAX_KEY_PACKAGE_B64_BYTES).is_err());
    }
}
