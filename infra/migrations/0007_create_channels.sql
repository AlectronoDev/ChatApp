-- A channel is a named message room that belongs to a server.
-- Channel names must be unique within a server.
CREATE TABLE channels (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id  UUID        NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    name       TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (server_id, name)
);

-- Efficiently list all channels in a server.
CREATE INDEX channels_server_idx ON channels (server_id);
