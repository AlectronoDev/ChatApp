-- Server policy: whether members may upload channel history handoff for invitees
-- (see docs/protocol.md §10.1). Default off; only the owner may change via API.
ALTER TABLE servers
ADD COLUMN allow_past_channel_history_for_new_members BOOLEAN NOT NULL DEFAULT false;
