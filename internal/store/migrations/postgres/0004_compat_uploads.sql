-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- See the SQLite migration of the same name for why the compatibility layer's
-- authentication key lives in its own table, and why the lifecycle is not
-- duplicated.
--
-- PostgreSQL can relax a NOT NULL in place, so unlike SQLite this needs no
-- table rebuild.

ALTER TABLE uploads ALTER COLUMN wrapped_file_key  DROP NOT NULL;
ALTER TABLE uploads ALTER COLUMN wrap_nonce        DROP NOT NULL;
ALTER TABLE uploads ALTER COLUMN metadata_envelope DROP NOT NULL;
ALTER TABLE uploads ALTER COLUMN metadata_nonce    DROP NOT NULL;

-- All four or none. A row with some of them is a row no reader can interpret,
-- and this is what makes "which protocol is this upload?" answerable from the
-- row itself.
ALTER TABLE uploads ADD CONSTRAINT uploads_envelope_all_or_none CHECK (
    (wrapped_file_key IS NULL AND wrap_nonce IS NULL
        AND metadata_envelope IS NULL AND metadata_nonce IS NULL)
    OR
    (wrapped_file_key IS NOT NULL AND wrap_nonce IS NOT NULL
        AND metadata_envelope IS NOT NULL AND metadata_nonce IS NOT NULL)
);

CREATE TABLE compat_uploads (
    id        TEXT PRIMARY KEY NOT NULL
              REFERENCES uploads (id) ON DELETE CASCADE,

    -- The client's HMAC key, in a form the server can compute with. The weaker
    -- model the compatibility layer speaks, confined to this table.
    auth_key  BYTEA NOT NULL,

    -- Replaced on every successful authentication, so a captured Authorization
    -- header cannot be replayed against the next request.
    nonce     BYTEA NOT NULL,

    -- The third-party client's own encrypted metadata, in that protocol's
    -- format rather than this project's.
    metadata  BYTEA NOT NULL,

    requires_password BOOLEAN NOT NULL DEFAULT FALSE
);
