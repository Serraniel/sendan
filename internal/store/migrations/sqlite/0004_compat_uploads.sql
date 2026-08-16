-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Storage for third-party compatibility uploads, kept in its own table.
--
-- The compatibility protocol has the server verify a download by computing an
-- HMAC itself, which means the server must hold the client's authentication key
-- in a form it can use. Sendan's own model never does: it stores a hash, so an
-- operator cannot produce a valid authenticator for an upload they did not
-- receive one for.
--
-- That weaker credential lives in a separate table rather than in a column of
-- `uploads`, so the difference is structural rather than a convention somebody
-- has to remember. A native upload has no row here, and nothing in the native
-- path reads or writes this table.
--
-- The lifecycle is deliberately *not* duplicated. Expiry, download counting,
-- reaping and the destruction of the at-rest key all continue to work from the
-- `uploads` row, so a compatibility upload expires and is shredded by exactly
-- the code that already does it, rather than by a second implementation that
-- could drift.

-- Four columns describe Sendan's own envelope, and a compatibility upload has
-- none of them: its client encrypts with a key the server never sees, so there
-- is no wrapped file key to store and no envelope in this project's format.
--
-- SQLite cannot drop a NOT NULL constraint in place, so the table is rebuilt.
-- The columns below are what 0001 created plus everything later migrations
-- added - bytes_served from 0002 and completed_at from 0003. A rebuild that
-- forgets one silently drops a column, which is why the conformance suite runs
-- against a migrated database rather than a freshly created one.
PRAGMA foreign_keys = OFF;

CREATE TABLE uploads_new (
    id                 TEXT    PRIMARY KEY NOT NULL,

    -- NULL together for a compatibility upload; present together otherwise.
    wrapped_file_key   BLOB,
    wrap_nonce         BLOB,
    metadata_envelope  BLOB,
    metadata_nonce     BLOB,

    auth_token_hash    BLOB    NOT NULL,
    owner_token_hash   BLOB    NOT NULL,
    at_rest_key        BLOB    NOT NULL,

    password_salt      BLOB,
    argon2_memory_kib  INTEGER,
    argon2_iterations  INTEGER,
    argon2_parallelism INTEGER,

    size               INTEGER NOT NULL,
    created_at         INTEGER NOT NULL,
    expires_at         INTEGER,
    max_downloads      INTEGER NOT NULL DEFAULT 0,
    download_count     INTEGER NOT NULL DEFAULT 0,
    bytes_served       INTEGER NOT NULL DEFAULT 0,
    completed_at       INTEGER,

    CHECK (size >= 0),
    CHECK (max_downloads >= 0),
    CHECK (download_count >= 0),
    CHECK (
        (password_salt IS NULL AND argon2_memory_kib IS NULL
            AND argon2_iterations IS NULL AND argon2_parallelism IS NULL)
        OR
        (password_salt IS NOT NULL AND argon2_memory_kib IS NOT NULL
            AND argon2_iterations IS NOT NULL AND argon2_parallelism IS NOT NULL)
    ),
    -- All four or none. A row with some of them is a row no reader can
    -- interpret, and this is the constraint that makes "which protocol is this
    -- upload?" answerable from the row itself.
    CHECK (
        (wrapped_file_key IS NULL AND wrap_nonce IS NULL
            AND metadata_envelope IS NULL AND metadata_nonce IS NULL)
        OR
        (wrapped_file_key IS NOT NULL AND wrap_nonce IS NOT NULL
            AND metadata_envelope IS NOT NULL AND metadata_nonce IS NOT NULL)
    )
);

INSERT INTO uploads_new
SELECT id, wrapped_file_key, wrap_nonce, metadata_envelope, metadata_nonce,
       auth_token_hash, owner_token_hash, at_rest_key,
       password_salt, argon2_memory_kib, argon2_iterations, argon2_parallelism,
       size, created_at, expires_at, max_downloads, download_count, bytes_served,
       completed_at
FROM uploads;

DROP TABLE uploads;
ALTER TABLE uploads_new RENAME TO uploads;

CREATE INDEX uploads_expires_at ON uploads (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX uploads_max_downloads ON uploads (max_downloads) WHERE max_downloads > 0;

PRAGMA foreign_keys = ON;

CREATE TABLE compat_uploads (
    id        TEXT PRIMARY KEY NOT NULL
              REFERENCES uploads (id) ON DELETE CASCADE,

    -- The client's HMAC key, in a form the server can compute with. This is the
    -- weaker model the compatibility layer exists to speak, and the reason it
    -- is confined to this table.
    auth_key  BLOB NOT NULL,

    -- Replaced on every successful authentication, so a captured Authorization
    -- header cannot be replayed against the next request.
    nonce     BLOB NOT NULL,

    -- The third-party client's own encrypted metadata. Opaque to the server, in
    -- that protocol's format rather than this project's.
    metadata  BLOB NOT NULL,

    -- Whether the uploader set a password. Disclosed by the protocol before any
    -- authentication, which is how its clients know to prompt.
    requires_password INTEGER NOT NULL DEFAULT 0,

    CHECK (requires_password IN (0, 1))
);
