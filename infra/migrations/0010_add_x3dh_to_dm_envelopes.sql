-- Add X3DH bootstrap metadata and protocol-version tracking to DM envelopes.
--
-- message_envelopes already has a `protocol TEXT DEFAULT 'DR'` column for the
-- high-level protocol type. This migration adds:
--
--   protocol_version  – numeric wire version so future incompatible changes can
--                       be detected and rejected without ambiguity.
--
--   x3dh_*            – public key material transmitted by the initiator
--                       alongside the first DR message of each new device-to-
--                       device session. NULL on all subsequent ratchet messages
--                       in the same session. The server stores and relays these
--                       fields opaquely; the responder uses them to reproduce
--                       the X3DH DH operations and derive the shared SK.
--
-- channel_envelopes does NOT get these columns: channels will use MLS (not
-- X3DH bootstrap) once that phase is implemented. A separate migration will add
-- MLS-specific metadata to channel_envelopes at that time.

ALTER TABLE message_envelopes
    ADD COLUMN protocol_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN x3dh_ik_dh_pub  TEXT,
    ADD COLUMN x3dh_ek_pub     TEXT,
    ADD COLUMN x3dh_spk_id     INTEGER,
    ADD COLUMN x3dh_otpk_id    INTEGER;

-- Structural invariant: ik_dh_pub, ek_pub, and spk_id must all be present
-- together or all absent. otpk_id is independently optional — it is absent
-- when the initiator found no one-time prekey for this device.
ALTER TABLE message_envelopes
    ADD CONSTRAINT x3dh_fields_consistent CHECK (
        (x3dh_ik_dh_pub IS NULL) = (x3dh_ek_pub IS NULL)
        AND (x3dh_ek_pub IS NULL) = (x3dh_spk_id IS NULL)
    );
