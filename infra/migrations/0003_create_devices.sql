-- A device represents a registered client with its own E2EE keypair.
-- Devices are separate from sessions: a session proves API auth; a device
-- holds the cryptographic identity used to encrypt and decrypt messages.
CREATE TABLE devices (
    id                UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    display_name      TEXT    NOT NULL,
    -- base64-encoded Ed25519 public key (signing / identity)
    identity_key      TEXT    NOT NULL,
    -- base64-encoded X25519 public key (key agreement / X3DH IK_DH)
    identity_dh_key   TEXT    NOT NULL,
    -- Signed prekey fields (X25519 keypair signed by the identity key)
    signed_prekey_id  INTEGER NOT NULL,
    signed_prekey_pub TEXT    NOT NULL,
    signed_prekey_sig TEXT    NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX devices_user_id_idx ON devices (user_id);

-- One-time prekeys are consumed one per X3DH session initiation.
CREATE TABLE device_one_time_prekeys (
    id          UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   UUID    NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,
    -- base64-encoded X25519 public key
    public_key  TEXT    NOT NULL,
    -- NULL = available; timestamp = consumed
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, key_id)
);

CREATE INDEX otpk_device_id_idx ON device_one_time_prekeys (device_id)
    WHERE consumed_at IS NULL;
