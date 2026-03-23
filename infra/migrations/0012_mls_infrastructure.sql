-- MLS (Message Layer Security) Delivery Service Infrastructure
--
-- The server acts as a pure Delivery Service (DS) per RFC 9420 §4.
-- It stores and fans out opaque TLS-encoded MLS objects. All cryptographic
-- state (ratchet trees, epoch key schedules, group secrets) lives on clients.
--
-- Object lifecycle:
--   KeyPackages → uploaded by each device; claimed one-at-a-time when
--                 another device adds this device to a new group (like OTPKs).
--   MLS Groups  → one per channel; tracks epoch and current member set so
--                 the server can enforce delivery to current members only.
--   MLS Messages → fan-out group messages (application ciphertexts + commits).
--   Welcome Msgs → per-device messages delivered to newly added members.

-- ─── MLS groups ───────────────────────────────────────────────────────────────

CREATE TABLE mls_groups (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- A channel may have at most one active MLS group.
    channel_id        UUID        NOT NULL UNIQUE REFERENCES channels(id) ON DELETE CASCADE,
    -- Opaque MLS group_id bytes chosen by the creator, base64-encoded.
    -- Distinct from our internal UUID; set by the MLS group creator.
    group_id_b64      TEXT        NOT NULL,
    -- Monotonically increasing epoch counter.
    -- The server enforces: accepted Commit must reference current_epoch.
    -- After acceptance: current_epoch advances to current_epoch + 1.
    current_epoch     BIGINT      NOT NULL DEFAULT 0 CHECK (current_epoch >= 0),
    creator_device_id UUID        NOT NULL REFERENCES devices(id),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── MLS KeyPackages ──────────────────────────────────────────────────────────

CREATE TABLE mls_key_packages (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id        UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    -- Opaque TLS-encoded KeyPackage, base64-encoded.
    -- Server validates size only; structure is opaque to the DS.
    key_package_data TEXT        NOT NULL,
    -- Set to NOW() when a committer claims this KP to build a Welcome.
    -- Once claimed, this KP must not be reused (like OTPKs in X3DH).
    claimed_at       TIMESTAMPTZ,
    -- Informational: which group consumed this KP.
    claimed_for_group UUID       REFERENCES mls_groups(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial index: only unclaimed KPs are interesting for claim queries.
CREATE INDEX mls_key_packages_device_unclaimed_idx
    ON mls_key_packages (device_id)
    WHERE claimed_at IS NULL;

-- ─── MLS group members ────────────────────────────────────────────────────────

-- Server-side member list, updated atomically with each accepted Commit.
-- This allows the DS to deliver messages only to current members, preventing
-- excluded devices from receiving post-removal traffic (defense-in-depth on
-- top of MLS cryptographic exclusion).
CREATE TABLE mls_group_members (
    group_id    UUID    NOT NULL REFERENCES mls_groups(id)  ON DELETE CASCADE,
    device_id   UUID    NOT NULL REFERENCES devices(id)     ON DELETE CASCADE,
    -- Epoch at which this device joined the group (for audit/debugging).
    added_epoch BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, device_id)
);

CREATE INDEX mls_group_members_device_idx ON mls_group_members (device_id);

-- ─── MLS messages (application + commits) ────────────────────────────────────

-- Unlike channel_envelopes (per-device ciphertexts), MLS messages are
-- group-level: a SINGLE ciphertext fan-out to all current group members.
-- Clients decrypt using the epoch key derived from the MLS key schedule.
CREATE TABLE mls_messages (
    -- Server-assigned UUID v7 for deterministic time-based ordering/pagination.
    id               UUID        PRIMARY KEY,
    -- Client-provided UUID v7 idempotency key.
    batch_id         UUID        NOT NULL,
    group_id         UUID        NOT NULL REFERENCES mls_groups(id) ON DELETE CASCADE,
    sender_device_id UUID        NOT NULL REFERENCES devices(id),
    -- 'application' = encrypted group message; 'commit' = group state change.
    message_type     TEXT        NOT NULL CHECK (message_type IN ('application', 'commit')),
    -- Epoch the message was created in.
    epoch            BIGINT      NOT NULL CHECK (epoch >= 0),
    -- Opaque TLS-encoded MLSMessage, base64-encoded.
    message_data     TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- One idempotent entry per (client batch, group).
    UNIQUE (batch_id, group_id)
);

-- Ordered cursor index for efficient pagination.
CREATE INDEX mls_messages_group_cursor_idx ON mls_messages (group_id, id);

-- ─── MLS Welcome messages (per new member) ────────────────────────────────────

-- Welcome messages are delivered only to the specific new member being added.
-- They are encrypted to that device's KeyPackage HPKE init key, so no one
-- else (including the server) can read the group secrets inside.
CREATE TABLE mls_welcome_messages (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id             UUID        NOT NULL REFERENCES mls_groups(id)  ON DELETE CASCADE,
    -- Commit that produced this Welcome; used to link add/remove operations.
    commit_batch_id      UUID        NOT NULL,
    recipient_device_id  UUID        NOT NULL REFERENCES devices(id)     ON DELETE CASCADE,
    -- Opaque TLS-encoded Welcome, base64-encoded.
    welcome_data         TEXT        NOT NULL,
    -- Epoch in which this member was added.
    epoch                BIGINT      NOT NULL CHECK (epoch >= 0),
    -- Delivery tracking: NULL = pending, non-NULL = fetched by recipient.
    delivered_at         TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX mls_welcome_messages_recipient_idx
    ON mls_welcome_messages (recipient_device_id)
    WHERE delivered_at IS NULL;
