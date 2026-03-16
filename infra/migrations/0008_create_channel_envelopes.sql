-- Channel messages use the same per-device envelope model as DM messages.
-- One logical send (a batch) produces one envelope per recipient device.
-- id is UUID v7 (time-ordered), generated server-side in Rust.
-- batch_id groups all envelopes belonging to one logical send operation.
CREATE TABLE channel_envelopes (
    id                  UUID        PRIMARY KEY,
    batch_id            UUID        NOT NULL,
    channel_id          UUID        NOT NULL REFERENCES channels (id) ON DELETE CASCADE,
    sender_user_id      UUID        NOT NULL REFERENCES users (id),
    -- RESTRICT: cannot delete a device that has sent channel messages.
    sender_device_id    UUID        NOT NULL REFERENCES devices (id),
    -- CASCADE: when a recipient device is deleted its pending envelopes go too.
    recipient_device_id UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    -- base64-encoded ciphertext, completely opaque to the server.
    ciphertext          TEXT        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL = pending delivery; set when the recipient device fetches the envelope.
    delivered_at        TIMESTAMPTZ
);

-- Fast lookup of undelivered envelopes for a given device.
CREATE INDEX ch_env_recipient_pending_idx
    ON channel_envelopes (recipient_device_id, id)
    WHERE delivered_at IS NULL;

-- Cursor-based history pagination per channel.
CREATE INDEX ch_env_channel_batch_idx
    ON channel_envelopes (channel_id, batch_id);
