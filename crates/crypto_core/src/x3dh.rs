//! X3DH (Extended Triple Diffie-Hellman) key agreement.
//!
//! Implements the Signal X3DH specification:
//! <https://signal.org/docs/specifications/x3dh/>
//!
//! X3DH establishes a shared secret (`SK`) between two parties using their
//! long-term identity DH keys, a medium-term signed prekey, and an optional
//! single-use one-time prekey. The resulting `SK` is handed directly to the
//! Double Ratchet to initialize the session.
//!
//! ## Key roles
//!
//! | Symbol     | Type    | Description |
//! |-----------|---------|-------------|
//! | `IK_A_dh` | X25519  | Alice's long-term identity DH key |
//! | `IK_B_dh` | X25519  | Bob's long-term identity DH key |
//! | `SPK_B`   | X25519  | Bob's signed prekey (rotated periodically) |
//! | `OPK_B`   | X25519  | Bob's one-time prekey (optional, single-use) |
//! | `EK_A`    | X25519  | Alice's ephemeral key (fresh per session) |
//!
//! ## DH computations (initiator side)
//!
//! ```text
//! DH1 = X25519(IK_A_dh,  SPK_B)
//! DH2 = X25519(EK_A,     IK_B_dh)
//! DH3 = X25519(EK_A,     SPK_B)
//! DH4 = X25519(EK_A,     OPK_B)   [if OPK_B present]
//! SK  = HKDF-SHA256(salt=0x00×32, ikm=0xFF×32‖DH1‖DH2‖DH3[‖DH4], info="chat-x3dh-v1")
//! ```

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::CryptoError;

/// 32 bytes of 0xFF prepended to the HKDF input key material, as required by
/// the X3DH spec. This ensures the derived key cannot be all-zero even if all
/// DH outputs are degenerate (impossible on Curve25519, but provides
/// defense-in-depth against implementation bugs).
const X3DH_F: [u8; 32] = [0xFF; 32];

/// Domain-separation label for the X3DH key derivation.
const X3DH_INFO: &[u8] = b"chat-x3dh-v1";

// ─── Public types ─────────────────────────────────────────────────────────────

/// Public portions of an X3DH session initiation sent by Alice to Bob,
/// alongside the first Double Ratchet message. Bob uses these fields to
/// reproduce Alice's DH computations and derive the same `SK`.
#[derive(Debug, Clone)]
pub struct X3dhInitMessage {
    /// Alice's X25519 identity DH public key (used by Bob for DH2).
    pub ik_dh_pub: [u8; 32],
    /// Alice's freshly generated ephemeral X25519 public key.
    pub ek_pub: [u8; 32],
    /// Identifies which of Bob's signed prekeys Alice consumed.
    pub spk_id: i32,
    /// Identifies which one-time prekey of Bob's Alice consumed, if any.
    pub otpk_id: Option<i32>,
}

// ─── Initiator side ───────────────────────────────────────────────────────────

/// Compute the X3DH shared secret as the **session initiator** (Alice).
///
/// Generates a fresh ephemeral key pair, performs three (or four) DH
/// operations, derives `SK` via HKDF-SHA256, and returns both `SK` and the
/// [`X3dhInitMessage`] that must be transmitted to Bob.
///
/// # Arguments
/// - `ik_a_dh_secret` — Alice's 32-byte X25519 identity DH private key
/// - `ik_b_dh_pub`    — Bob's 32-byte X25519 identity DH public key
/// - `spk_b_pub`      — Bob's 32-byte signed prekey public key
/// - `spk_b_id`       — Bob's signed prekey identifier (so Bob can look up his secret)
/// - `otpk_b`         — Bob's one-time prekey `(public_bytes, key_id)`, if available
pub fn x3dh_initiate(
    ik_a_dh_secret: &[u8; 32],
    ik_b_dh_pub: &[u8; 32],
    spk_b_pub: &[u8; 32],
    spk_b_id: i32,
    otpk_b: Option<(&[u8; 32], i32)>,
) -> Result<([u8; 32], X3dhInitMessage), CryptoError> {
    // Generate a fresh ephemeral X25519 key pair for this session.
    let mut ek_secret_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut ek_secret_bytes);
    let ek_secret = StaticSecret::from(ek_secret_bytes);
    let ek_pub = X25519Public::from(&ek_secret);

    let ik_a = StaticSecret::from(*ik_a_dh_secret);
    let ik_a_pub = X25519Public::from(&ik_a);

    let ik_b = X25519Public::from(*ik_b_dh_pub);
    let spk_b = X25519Public::from(*spk_b_pub);

    // DH1 = X25519(IK_A_dh,  SPK_B)
    let dh1 = ik_a.diffie_hellman(&spk_b);
    // DH2 = X25519(EK_A,     IK_B_dh)
    let dh2 = ek_secret.diffie_hellman(&ik_b);
    // DH3 = X25519(EK_A,     SPK_B)
    let dh3 = ek_secret.diffie_hellman(&spk_b);

    let (sk, otpk_id) = match otpk_b {
        Some((otpk_pub_bytes, id)) => {
            // DH4 = X25519(EK_A, OPK_B)
            let dh4 = ek_secret.diffie_hellman(&X25519Public::from(*otpk_pub_bytes));
            let sk = kdf_sk(&[dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), dh4.as_bytes()]);
            (sk, Some(id))
        }
        None => {
            let sk = kdf_sk(&[dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()]);
            (sk, None)
        }
    };

    let init = X3dhInitMessage {
        ik_dh_pub: *ik_a_pub.as_bytes(),
        ek_pub: *ek_pub.as_bytes(),
        spk_id: spk_b_id,
        otpk_id,
    };

    Ok((sk, init))
}

// ─── Responder side ───────────────────────────────────────────────────────────

/// Compute the X3DH shared secret as the **session responder** (Bob).
///
/// Reproduces Alice's DH computations in the symmetric Diffie-Hellman order
/// to derive the same `SK`. Bob must supply the private keys that correspond
/// to the prekey IDs Alice recorded in the [`X3dhInitMessage`].
///
/// # Arguments
/// - `ik_b_dh_secret`  — Bob's 32-byte X25519 identity DH private key
/// - `spk_b_secret`    — Bob's 32-byte signed prekey private key that Alice used
/// - `otpk_b_secret`   — Bob's 32-byte one-time prekey private key, if Alice used one
/// - `init`            — The [`X3dhInitMessage`] received from Alice
pub fn x3dh_respond(
    ik_b_dh_secret: &[u8; 32],
    spk_b_secret: &[u8; 32],
    otpk_b_secret: Option<&[u8; 32]>,
    init: &X3dhInitMessage,
) -> Result<[u8; 32], CryptoError> {
    let ik_b = StaticSecret::from(*ik_b_dh_secret);
    let spk_b = StaticSecret::from(*spk_b_secret);
    let ik_a = X25519Public::from(init.ik_dh_pub);
    let ek_a = X25519Public::from(init.ek_pub);

    // DH1 = X25519(SPK_B,    IK_A_dh)   [== Alice's DH1]
    let dh1 = spk_b.diffie_hellman(&ik_a);
    // DH2 = X25519(IK_B_dh,  EK_A)      [== Alice's DH2]
    let dh2 = ik_b.diffie_hellman(&ek_a);
    // DH3 = X25519(SPK_B,    EK_A)      [== Alice's DH3]
    let dh3 = spk_b.diffie_hellman(&ek_a);

    let sk = match otpk_b_secret {
        Some(otpk_secret) => {
            // DH4 = X25519(OPK_B, EK_A) [== Alice's DH4]
            let dh4 = StaticSecret::from(*otpk_secret).diffie_hellman(&ek_a);
            kdf_sk(&[dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), dh4.as_bytes()])
        }
        None => kdf_sk(&[dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()]),
    };

    Ok(sk)
}

// ─── Internal KDF ─────────────────────────────────────────────────────────────

/// HKDF-SHA256-based key derivation for X3DH.
///
/// Prepends the 32-byte `F` constant (all `0xFF`) to the concatenated DH
/// outputs before HKDF, matching the Signal X3DH specification.
fn kdf_sk(dh_outputs: &[&[u8]]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + dh_outputs.len() * 32);
    ikm.extend_from_slice(&X3DH_F);
    for dh in dh_outputs {
        ikm.extend_from_slice(dh);
    }

    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut sk = [0u8; 32];
    hkdf.expand(X3DH_INFO, &mut sk)
        .expect("32 bytes is within the HKDF-SHA256 output limit");
    sk
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_x25519_secret() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes
    }

    fn x25519_pub(secret: &[u8; 32]) -> [u8; 32] {
        *X25519Public::from(&StaticSecret::from(*secret)).as_bytes()
    }

    struct KeySet {
        ik_dh_secret: [u8; 32],
        ik_dh_pub: [u8; 32],
        spk_secret: [u8; 32],
        spk_pub: [u8; 32],
        spk_id: i32,
        otpk_secret: [u8; 32],
        otpk_pub: [u8; 32],
        otpk_id: i32,
    }

    impl KeySet {
        fn generate() -> Self {
            let ik_dh_secret = random_x25519_secret();
            let spk_secret = random_x25519_secret();
            let otpk_secret = random_x25519_secret();
            Self {
                ik_dh_pub: x25519_pub(&ik_dh_secret),
                ik_dh_secret,
                spk_pub: x25519_pub(&spk_secret),
                spk_secret,
                spk_id: 1,
                otpk_pub: x25519_pub(&otpk_secret),
                otpk_secret,
                otpk_id: 42,
            }
        }
    }

    #[test]
    fn both_parties_derive_same_sk_with_otpk() {
        let alice_ik_secret = random_x25519_secret();
        let bob = KeySet::generate();

        let (alice_sk, init) = x3dh_initiate(
            &alice_ik_secret,
            &bob.ik_dh_pub,
            &bob.spk_pub,
            bob.spk_id,
            Some((&bob.otpk_pub, bob.otpk_id)),
        )
        .unwrap();

        let bob_sk = x3dh_respond(
            &bob.ik_dh_secret,
            &bob.spk_secret,
            Some(&bob.otpk_secret),
            &init,
        )
        .unwrap();

        assert_eq!(alice_sk, bob_sk, "both parties must derive the same SK");
    }

    #[test]
    fn both_parties_derive_same_sk_without_otpk() {
        let alice_ik_secret = random_x25519_secret();
        let bob = KeySet::generate();

        let (alice_sk, init) = x3dh_initiate(
            &alice_ik_secret,
            &bob.ik_dh_pub,
            &bob.spk_pub,
            bob.spk_id,
            None,
        )
        .unwrap();

        let bob_sk = x3dh_respond(&bob.ik_dh_secret, &bob.spk_secret, None, &init).unwrap();

        assert_eq!(alice_sk, bob_sk);
    }

    #[test]
    fn different_sessions_produce_different_sks() {
        let alice_ik_secret = random_x25519_secret();
        let bob = KeySet::generate();

        let (sk1, _) = x3dh_initiate(
            &alice_ik_secret,
            &bob.ik_dh_pub,
            &bob.spk_pub,
            bob.spk_id,
            None,
        )
        .unwrap();

        let (sk2, _) = x3dh_initiate(
            &alice_ik_secret,
            &bob.ik_dh_pub,
            &bob.spk_pub,
            bob.spk_id,
            None,
        )
        .unwrap();

        // Each session generates a fresh ephemeral key, so SKs must differ.
        assert_ne!(sk1, sk2, "fresh ephemeral keys must produce distinct SKs");
    }

    #[test]
    fn wrong_otpk_secret_produces_different_sk() {
        let alice_ik_secret = random_x25519_secret();
        let bob = KeySet::generate();

        let (alice_sk, init) = x3dh_initiate(
            &alice_ik_secret,
            &bob.ik_dh_pub,
            &bob.spk_pub,
            bob.spk_id,
            Some((&bob.otpk_pub, bob.otpk_id)),
        )
        .unwrap();

        let wrong_otpk_secret = random_x25519_secret();
        let bob_sk_wrong = x3dh_respond(
            &bob.ik_dh_secret,
            &bob.spk_secret,
            Some(&wrong_otpk_secret),
            &init,
        )
        .unwrap();

        assert_ne!(
            alice_sk, bob_sk_wrong,
            "wrong OPK secret must not reproduce SK"
        );
    }

    #[test]
    fn sk_without_otpk_differs_from_sk_with_otpk() {
        let alice_ik_secret = random_x25519_secret();
        let bob = KeySet::generate();

        let (sk_with, _) = x3dh_initiate(
            &alice_ik_secret,
            &bob.ik_dh_pub,
            &bob.spk_pub,
            bob.spk_id,
            Some((&bob.otpk_pub, bob.otpk_id)),
        )
        .unwrap();

        let (sk_without, _) = x3dh_initiate(
            &alice_ik_secret,
            &bob.ik_dh_pub,
            &bob.spk_pub,
            bob.spk_id,
            None,
        )
        .unwrap();

        assert_ne!(
            sk_with, sk_without,
            "presence of OPK must change the derived SK"
        );
    }
}
