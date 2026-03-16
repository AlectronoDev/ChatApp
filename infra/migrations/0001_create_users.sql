CREATE TABLE users (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username         TEXT        NOT NULL UNIQUE,
    password_hash    TEXT        NOT NULL,
    -- SHA-256 hex of the one-time recovery code (high-entropy random token).
    recovery_code_hash TEXT      NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX users_username_idx ON users (username);
