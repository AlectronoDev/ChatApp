-- Ratchet state safety: idempotency constraints and encrypted session storage.
--
-- Two independent concerns are addressed here:
--
-- 1. IDEMPOTENT MESSAGE DELIVERY
--    A given (batch_id, recipient_device_id) pair must only be inserted once.
--    This lets clients retry a send with the same batch_id without creating
--    duplicate envelopes, which would corrupt the recipient's ratchet counter.
--    The server checks for an existing batch before inserting and returns the
--    original response if found, so retries are transparent to the sender too.
--
-- 2. ENCRYPTED RATCHET SESSION STATE STORAGE
--    Clients can optionally back up their encrypted ratchet session state to
--    the server. The encrypted_state blob is opaque to the server — it is
--    encrypted client-side with a key derived from the device's private key.
--    The server stores and returns it verbatim.
--    Optimistic locking (version counter) ensures concurrent updates from the
--    same device (e.g. two browser tabs) are detected and rejected cleanly.

-- ─── Idempotency constraints ─────────────────────────────────────────────────

ALTER TABLE message_envelopes
    ADD CONSTRAINT msg_env_batch_device_unique
    UNIQUE (batch_id, recipient_device_id);

ALTER TABLE channel_envelopes
    ADD CONSTRAINT ch_env_batch_device_unique
    UNIQUE (batch_id, recipient_device_id);

-- ─── Encrypted ratchet session state ─────────────────────────────────────────

CREATE TABLE ratchet_sessions (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The device that owns this session state record.
    -- CASCADE: deleting a device removes all its session backups.
    owner_device_id  UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    -- The peer device this session is with. No CASCADE here — we may want to
    -- retain state metadata even if the peer device is later removed.
    peer_device_id   UUID        NOT NULL REFERENCES devices (id),
    -- Monotonically increasing version. Starts at 1 on first write.
    -- The client must present the current version to perform an update;
    -- a mismatch → 409 Conflict (stale read — re-read and retry).
    version          BIGINT      NOT NULL DEFAULT 0 CHECK (version >= 0),
    -- Opaque encrypted session state, base64-encoded. The server cannot read
    -- this; it stores and returns it verbatim without any transformation.
    -- Maximum: 64 KiB encoded, enforced at the application layer.
    encrypted_state  TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One state record per directed session. (A↔B produces two records:
    -- one owned by A and one owned by B, independently versioned.)
    UNIQUE (owner_device_id, peer_device_id)
);

-- Quick lookup when a device fetches all its active session state records.
CREATE INDEX ratchet_sessions_owner_idx ON ratchet_sessions (owner_device_id);
