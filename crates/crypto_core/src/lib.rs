//! Cryptographic primitives for the chat application.
//!
//! All application-level encryption, decryption, key generation, and key
//! derivation must go through this crate. No other crate should contain
//! raw cryptographic logic.
//!
//! ## Protocol
//! - **X3DH** (`x3dh` module): Extended Triple Diffie-Hellman key agreement,
//!   following the Signal X3DH specification, used to establish a shared
//!   secret between two devices without prior contact.
//! - **Double Ratchet** (`double_ratchet` module): Signal Double Ratchet
//!   algorithm providing forward secrecy and break-in recovery for DMs.
//! - **Legacy ECDH** (this module): Static ECDH session key derivation kept
//!   for reference only; all new code should use X3DH + Double Ratchet.

pub mod double_ratchet;
pub mod x3dh;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("invalid key length")]
    InvalidKeyLength,

    #[error("invalid Ed25519 key: point is not on the curve")]
    InvalidKeyEncoding,

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed — wrong key, corrupted ciphertext, or tampered AAD")]
    DecryptionFailed,

    #[error("key derivation failed")]
    KeyDerivation,

    /// The peer skipped more messages than the allowed safety limit. Either
    /// the sender is misbehaving or there is a severe message-loss event.
    #[error("too many skipped messages (limit: {limit})")]
    TooManySkippedMessages { limit: u32 },

    /// An operation was attempted on a Double Ratchet session that has not
    /// been fully initialized yet (e.g. the receiver trying to send before
    /// receiving the initiator's first message).
    #[error("ratchet session is not yet fully initialized for this operation")]
    SessionNotInitialized,

    /// Session state could not be serialized or deserialized.
    #[error("session serialization error: {0}")]
    Serialization(String),
}

// ─── Key material ─────────────────────────────────────────────────────────────

/// Raw device key bytes. Kept as plain arrays so they can be base64-encoded
/// and persisted to disk by the caller without exposing dalek internals.
pub struct DeviceKeyMaterial {
    /// 32-byte Ed25519 signing seed.
    pub signing_seed: [u8; 32],
    /// 32-byte X25519 DH secret.
    pub dh_secret: [u8; 32],
    /// 32-byte X25519 signed prekey secret.
    pub signed_prekey_secret: [u8; 32],
    pub signed_prekey_id: i32,
}

/// Public key strings ready to POST to the server's device-registration endpoint.
pub struct DevicePublicKeys {
    /// base64-encoded Ed25519 public key (device identity).
    pub identity_key: String,
    /// base64-encoded X25519 public key (DH identity key for session establishment).
    pub identity_dh_key: String,
    pub signed_prekey_id: i32,
    /// base64-encoded X25519 signed prekey public key.
    pub signed_prekey_pub: String,
    /// base64-encoded Ed25519 signature over (key_id_be || prekey_pub_bytes).
    pub signed_prekey_sig: String,
}

/// Generate a complete set of device key material plus the public keys to
/// register with the server.
pub fn generate_device_keys() -> (DeviceKeyMaterial, DevicePublicKeys) {
    let mut rng = rand::rngs::OsRng;

    // Ed25519 signing key (device identity)
    let mut signing_bytes = [0u8; 32];
    rng.fill_bytes(&mut signing_bytes);
    let signing_key = SigningKey::from_bytes(&signing_bytes);

    // X25519 DH key (long-term, for ECDH session derivation)
    let mut dh_bytes = [0u8; 32];
    rng.fill_bytes(&mut dh_bytes);
    let dh_secret = StaticSecret::from(dh_bytes);
    let dh_pub = X25519Public::from(&dh_secret);

    // X25519 signed prekey (rotated periodically)
    let mut spk_bytes = [0u8; 32];
    rng.fill_bytes(&mut spk_bytes);
    let spk_secret = StaticSecret::from(spk_bytes);
    let spk_pub = X25519Public::from(&spk_secret);
    let signed_prekey_id: i32 = 1;

    // Sign (key_id_be || spk_pub_bytes) to prove the prekey is authentic.
    let mut to_sign = [0u8; 4 + 32];
    to_sign[..4].copy_from_slice(&signed_prekey_id.to_be_bytes());
    to_sign[4..].copy_from_slice(spk_pub.as_bytes());
    let signature = signing_key.sign(&to_sign);

    let public_keys = DevicePublicKeys {
        identity_key: B64.encode(signing_key.verifying_key().as_bytes()),
        identity_dh_key: B64.encode(dh_pub.as_bytes()),
        signed_prekey_id,
        signed_prekey_pub: B64.encode(spk_pub.as_bytes()),
        signed_prekey_sig: B64.encode(signature.to_bytes()),
    };

    let material = DeviceKeyMaterial {
        signing_seed: *signing_key.as_bytes(),
        dh_secret: dh_bytes,
        signed_prekey_secret: spk_bytes,
        signed_prekey_id,
    };

    (material, public_keys)
}

/// Derive the X25519 public key from its corresponding secret bytes.
///
/// Used to produce our own DH public key on the fly — e.g. when creating a
/// self-envelope so a sender can decrypt their own sent messages.
pub fn dh_public_key_b64(secret_bytes: &[u8; 32]) -> String {
    let secret = StaticSecret::from(*secret_bytes);
    B64.encode(X25519Public::from(&secret).as_bytes())
}

// ─── Key validation helpers ───────────────────────────────────────────────────

/// Decode a base64-encoded Ed25519 verifying key, returning the raw 32 bytes.
///
/// Returns an error if the string is not valid base64 or the decoded length is
/// not exactly 32 bytes. Does not validate that the point lies on the curve —
/// use [`verify_signed_prekey`] for full cryptographic validation.
pub fn decode_ed25519_pubkey(b64: &str) -> Result<[u8; 32], CryptoError> {
    B64.decode(b64)?
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)
}

/// Decode a base64-encoded X25519 public key, returning the raw 32 bytes.
///
/// Returns an error if the string is not valid base64 or the decoded length is
/// not exactly 32 bytes. All 32-byte values are valid X25519 keys after
/// Curve25519 clamping, so no further point validation is needed.
pub fn decode_x25519_pubkey(b64: &str) -> Result<[u8; 32], CryptoError> {
    B64.decode(b64)?
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)
}

/// Verify that a signed prekey carries a valid Ed25519 signature from the
/// device's identity key.
///
/// The signed message format is `key_id_be32 || prekey_pub_bytes`, which
/// matches the format produced by [`generate_device_keys`]. This prevents a
/// malicious server from substituting an attacker-controlled prekey while
/// still serving the client's real identity key.
pub fn verify_signed_prekey(
    identity_key_b64: &str,
    key_id: i32,
    prekey_pub_b64: &str,
    signature_b64: &str,
) -> Result<(), CryptoError> {
    let ik_bytes: [u8; 32] = decode_ed25519_pubkey(identity_key_b64)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&ik_bytes)
        .map_err(|_| CryptoError::InvalidKeyEncoding)?;

    let spk_bytes: [u8; 32] = decode_x25519_pubkey(prekey_pub_b64)?;

    let sig_bytes: [u8; 64] = B64
        .decode(signature_b64)?
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let mut message = [0u8; 4 + 32];
    message[..4].copy_from_slice(&key_id.to_be_bytes());
    message[4..].copy_from_slice(&spk_bytes);

    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

// ─── Encryption / Decryption ──────────────────────────────────────────────────

/// Encrypt `plaintext` for a peer device using our DH secret and their DH
/// public key. `aad` (additional authenticated data, e.g. thread_id bytes)
/// is authenticated but not encrypted — tampering with it causes decryption
/// to fail.
///
/// Returns `base64(nonce[12] || chacha20poly1305_ciphertext_with_tag)`.
pub fn encrypt_for_device(
    our_dh_secret_bytes: &[u8; 32],
    their_dh_pub_b64: &str,
    plaintext: &str,
    aad: &[u8],
) -> Result<String, CryptoError> {
    let session_key = ecdh_session_key(our_dh_secret_bytes, their_dh_pub_b64)?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let key = Key::from_slice(&session_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext.as_bytes(), aad })
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(B64.encode(combined))
}

/// Decrypt a ciphertext envelope produced by [`encrypt_for_device`].
/// Requires our DH secret and the *sender's* DH public key to re-derive the
/// same session key.
pub fn decrypt_from_device(
    our_dh_secret_bytes: &[u8; 32],
    their_dh_pub_b64: &str,
    ciphertext_b64: &str,
    aad: &[u8],
) -> Result<String, CryptoError> {
    let session_key = ecdh_session_key(our_dh_secret_bytes, their_dh_pub_b64)?;

    let combined = B64.decode(ciphertext_b64)?;
    if combined.len() < 13 {
        return Err(CryptoError::DecryptionFailed);
    }

    let nonce = Nonce::from_slice(&combined[..12]);
    let encrypted = &combined[12..];

    let key = Key::from_slice(&session_key);
    let cipher = ChaCha20Poly1305::new(key);

    let plaintext_bytes = cipher
        .decrypt(nonce, Payload { msg: encrypted, aad })
        .map_err(|_| CryptoError::DecryptionFailed)?;

    String::from_utf8(plaintext_bytes).map_err(|_| CryptoError::DecryptionFailed)
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Derive a 32-byte ChaCha20 session key from an X25519 ECDH exchange.
///
/// Both sides compute the same value:
///   ECDH(our_secret, their_public) == ECDH(their_secret, our_public)
///
/// The raw DH output is fed into HKDF-SHA256 with a domain-separation label
/// to produce the final key.
fn ecdh_session_key(
    our_secret_bytes: &[u8; 32],
    their_pub_b64: &str,
) -> Result<[u8; 32], CryptoError> {
    let their_bytes: [u8; 32] = B64
        .decode(their_pub_b64)?
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;

    let our_secret = StaticSecret::from(*our_secret_bytes);
    let their_pub = X25519Public::from(their_bytes);
    let shared = our_secret.diffie_hellman(&their_pub);

    let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(b"chat-app-dm-session-key-v1", &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(key)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let (alice_mat, alice_pub) = generate_device_keys();
        let (bob_mat, bob_pub) = generate_device_keys();

        let aad = b"thread-id-bytes";
        let plaintext = "Hello, Bob!";

        // Alice encrypts for Bob.
        let ciphertext =
            encrypt_for_device(&alice_mat.dh_secret, &bob_pub.identity_dh_key, plaintext, aad)
                .unwrap();

        // Bob decrypts using Alice's public DH key.
        let decrypted =
            decrypt_from_device(&bob_mat.dh_secret, &alice_pub.identity_dh_key, &ciphertext, aad)
                .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_aad_fails_decryption() {
        let (alice_mat, _) = generate_device_keys();
        let (bob_mat, bob_pub) = generate_device_keys();
        let (_, alice_pub) = generate_device_keys();

        let ciphertext =
            encrypt_for_device(&alice_mat.dh_secret, &bob_pub.identity_dh_key, "secret", b"correct-aad")
                .unwrap();

        let result =
            decrypt_from_device(&bob_mat.dh_secret, &alice_pub.identity_dh_key, &ciphertext, b"wrong-aad");

        assert!(result.is_err());
    }

    #[test]
    fn signed_prekey_verification_succeeds_for_valid_keys() {
        let (_, pub_keys) = generate_device_keys();

        assert!(verify_signed_prekey(
            &pub_keys.identity_key,
            pub_keys.signed_prekey_id,
            &pub_keys.signed_prekey_pub,
            &pub_keys.signed_prekey_sig,
        )
        .is_ok());
    }

    #[test]
    fn signed_prekey_verification_fails_for_wrong_identity_key() {
        let (_, pub_keys) = generate_device_keys();
        let (_, other) = generate_device_keys();

        let result = verify_signed_prekey(
            &other.identity_key, // wrong key
            pub_keys.signed_prekey_id,
            &pub_keys.signed_prekey_pub,
            &pub_keys.signed_prekey_sig,
        );
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn signed_prekey_verification_fails_for_tampered_prekey() {
        let (_, pub_keys) = generate_device_keys();
        let (_, other) = generate_device_keys();

        let result = verify_signed_prekey(
            &pub_keys.identity_key,
            pub_keys.signed_prekey_id,
            &other.signed_prekey_pub, // tampered
            &pub_keys.signed_prekey_sig,
        );
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn signed_prekey_verification_fails_for_wrong_key_id() {
        let (_, pub_keys) = generate_device_keys();

        let result = verify_signed_prekey(
            &pub_keys.identity_key,
            pub_keys.signed_prekey_id + 1, // wrong id changes the message
            &pub_keys.signed_prekey_pub,
            &pub_keys.signed_prekey_sig,
        );
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    #[test]
    fn decode_ed25519_pubkey_rejects_wrong_length() {
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(matches!(
            decode_ed25519_pubkey(&short),
            Err(CryptoError::InvalidKeyLength)
        ));
    }

    #[test]
    fn decode_x25519_pubkey_rejects_wrong_length() {
        let long = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        assert!(matches!(
            decode_x25519_pubkey(&long),
            Err(CryptoError::InvalidKeyLength)
        ));
    }
}
