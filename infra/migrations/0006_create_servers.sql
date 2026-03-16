-- A server is a named community that owns one or more channels.
-- The user who creates a server automatically becomes its owner.
CREATE TABLE servers (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    -- Kept for auditing; does NOT cascade-delete on user removal so the
    -- server survives if the owner account is deleted.
    created_by  UUID        NOT NULL REFERENCES users (id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Membership table with a simple two-level role: owner or member.
-- A server always has exactly one owner (enforced at the application layer).
CREATE TABLE server_members (
    server_id  UUID        NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- 'owner' | 'member'
    role       TEXT        NOT NULL DEFAULT 'member',
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (server_id, user_id)
);

-- Efficiently list all servers a user belongs to.
CREATE INDEX server_members_user_idx ON server_members (user_id);
