-- Each logical message (batch) produces one envelope per recipient device.
-- id is UUID v7 (time-ordered), generated server-side in Rust.
-- batch_id groups all envelopes belonging to one logical send operation.
CREATE TABLE message_envelopes (
    id                  UUID        PRIMARY KEY,
    batch_id            UUID        NOT NULL,
    thread_id           UUID        NOT NULL REFERENCES dm_threads (id) ON DELETE CASCADE,
    sender_user_id      UUID        NOT NULL REFERENCES users (id),
    -- RESTRICT: cannot delete a device that has sent messages. A future
    -- migration will handle device tombstoning properly.
    sender_device_id    UUID        NOT NULL REFERENCES devices (id),
    -- CASCADE: when a recipient device is deleted its pending envelopes go too.
    recipient_device_id UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    -- "DR" (Double Ratchet for DMs) or "MLS" (group channels — future).
    protocol            TEXT        NOT NULL DEFAULT 'DR',
    -- base64-encoded ciphertext, completely opaque to the server.
    ciphertext          TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL = pending delivery; set when the recipient device fetches the envelope.
    delivered_at        TIMESTAMPTZ
);

-- Fast lookup of pending envelopes for a given device.
CREATE INDEX msg_env_recipient_pending_idx
    ON message_envelopes (recipient_device_id, id)
    WHERE delivered_at IS NULL;

-- Cursor-based history pagination per thread.
CREATE INDEX msg_env_thread_batch_idx
    ON message_envelopes (thread_id, batch_id);
