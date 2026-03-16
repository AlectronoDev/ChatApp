//! Cryptographic primitives for the chat application.
//!
//! All application-level encryption, decryption, key generation, and key
//! derivation must go through this crate. No other crate should contain
//! raw cryptographic logic.
//!
//! ## Protocol note
//! This implements a *simplified* session model for the CLI demo:
//! - X25519 ECDH to establish a shared secret between two device DH keys
//! - HKDF-SHA256 to derive a symmetric session key
//! - ChaCha20-Poly1305 AEAD for message encryption
//!
//! This provides real confidentiality and authenticity but NOT forward secrecy
//! (no Double Ratchet) and NOT X3DH ephemeral key exchange. Full X3DH + Double
//! Ratchet will be layered in once the core infrastructure is validated.

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

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed — wrong key, corrupted ciphertext, or tampered AAD")]
    DecryptionFailed,

    #[error("key derivation failed")]
    KeyDerivation,
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
}
