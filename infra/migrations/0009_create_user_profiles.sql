CREATE TABLE user_profiles (
    user_id      UUID        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    display_name TEXT,
    bio          TEXT,
    avatar_url   TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
