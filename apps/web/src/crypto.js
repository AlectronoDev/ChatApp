/**
 * E2EE cryptographic primitives for the web client.
 *
 * Every function here produces output **bitwise-identical** to its counterpart
 * in `crates/crypto_core/src/lib.rs`.  The algorithm chain is:
 *   X25519 ECDH  →  HKDF-SHA256  →  ChaCha20-Poly1305
 *
 * Ciphertext wire format: base64( nonce[12] || chacha20poly1305_ct_with_tag )
 * AAD for DMs:      UUID bytes of thread_id  (16 bytes)
 * AAD for channels: UUID bytes of channel_id (16 bytes)
 */
import { x25519, ed25519 } from '@noble/curves/ed25519';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
// ─── Base64 helpers ───────────────────────────────────────────────────────────
export function bytesToB64(bytes) {
    let binary = '';
    for (const b of bytes)
        binary += String.fromCharCode(b);
    return btoa(binary);
}
export function b64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++)
        bytes[i] = binary.charCodeAt(i);
    return bytes;
}
/**
 * Convert a UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) to its 16-byte
 * representation. Used to produce the AAD bytes passed to encrypt/decrypt.
 */
export function uuidToBytes(uuid) {
    const hex = uuid.replace(/-/g, '');
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++)
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
}
// ─── Key generation ───────────────────────────────────────────────────────────
/** Generate a complete device key bundle, mirroring `generate_device_keys()`. */
export function generateDeviceKeys() {
    // Ed25519 identity key
    const signingSecret = randomBytes(32);
    const identityKey = ed25519.getPublicKey(signingSecret);
    // X25519 DH identity key
    const dhSecret = randomBytes(32);
    const dhPublic = x25519.getPublicKey(dhSecret);
    // X25519 signed prekey
    const spkSecret = randomBytes(32);
    const spkPub = x25519.getPublicKey(spkSecret);
    const signedPrekeyId = 1;
    // Sign (key_id_be || spk_pub_bytes) with Ed25519 identity key
    const toSign = new Uint8Array(4 + 32);
    new DataView(toSign.buffer).setInt32(0, signedPrekeyId, false); // big-endian
    toSign.set(spkPub, 4);
    const sig = ed25519.sign(toSign, signingSecret);
    return {
        dhSecretB64: bytesToB64(dhSecret),
        dhPublicB64: bytesToB64(dhPublic),
        signingSecretB64: bytesToB64(signingSecret),
        identityKeyB64: bytesToB64(identityKey),
        signedPrekeySecretB64: bytesToB64(spkSecret),
        signedPrekeyPubB64: bytesToB64(spkPub),
        signedPrekeySigB64: bytesToB64(sig),
        signedPrekeyId,
    };
}
/** Derive the X25519 public key from its secret. Used for self-envelopes. */
export function dhPublicKeyB64(secretB64) {
    return bytesToB64(x25519.getPublicKey(b64ToBytes(secretB64)));
}
// ─── Session key derivation ───────────────────────────────────────────────────
/**
 * X25519 ECDH followed by HKDF-SHA256.
 * Mirrors `ecdh_session_key()` in Rust — both sides produce the same 32-byte key.
 */
function ecdhSessionKey(ourSecretB64, theirPublicB64) {
    const ourSecret = b64ToBytes(ourSecretB64);
    const theirPublic = b64ToBytes(theirPublicB64);
    const shared = x25519.getSharedSecret(ourSecret, theirPublic);
    // Same domain-separation label as the Rust implementation.
    return hkdf(sha256, shared, undefined, 'chat-app-dm-session-key-v1', 32);
}
// ─── Encrypt / Decrypt ────────────────────────────────────────────────────────
/**
 * Encrypt `plaintext` for a peer device.
 * Mirrors `encrypt_for_device()` in Rust.
 * Returns base64( nonce[12] || chacha20poly1305_ciphertext_with_tag ).
 */
export function encryptForDevice(ourSecretB64, theirPublicB64, plaintext, aad) {
    const key = ecdhSessionKey(ourSecretB64, theirPublicB64);
    const nonce = randomBytes(12);
    const cipher = chacha20poly1305(key, nonce, aad);
    const ct = cipher.encrypt(new TextEncoder().encode(plaintext));
    const combined = new Uint8Array(12 + ct.length);
    combined.set(nonce, 0);
    combined.set(ct, 12);
    return bytesToB64(combined);
}
/**
 * Decrypt a ciphertext produced by `encryptForDevice`.
 * Mirrors `decrypt_from_device()` in Rust.
 */
export function decryptFromDevice(ourSecretB64, theirPublicB64, ciphertextB64, aad) {
    const key = ecdhSessionKey(ourSecretB64, theirPublicB64);
    const combined = b64ToBytes(ciphertextB64);
    if (combined.length < 13)
        throw new Error('ciphertext too short');
    const nonce = combined.slice(0, 12);
    const ct = combined.slice(12);
    const cipher = chacha20poly1305(key, nonce, aad);
    const plaintext = cipher.decrypt(ct);
    return new TextDecoder().decode(plaintext);
}
