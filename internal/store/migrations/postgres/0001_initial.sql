-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- There is deliberately no deleted_at column, no soft-delete flag, and no audit
-- table keyed by upload identifier. Sendan promises that an expired upload
-- leaves nothing behind, and a schema that can retain a tombstone makes that
-- promise impossible to keep. Deletion removes the row.

CREATE TABLE uploads (
    id                 TEXT        PRIMARY KEY NOT NULL,

    -- Client-produced ciphertext. Opaque to the server.
    wrapped_file_key   BYTEA    NOT NULL,
    wrap_nonce         BYTEA    NOT NULL,
    metadata_envelope  BYTEA    NOT NULL,
    metadata_nonce     BYTEA    NOT NULL,

    -- Hashes only. The server never holds either token.
    auth_token_hash    BYTEA    NOT NULL,
    owner_token_hash   BYTEA    NOT NULL,

    -- Deleting this row destroys the blob's at-rest key, and with it the
    -- content. See internal/blob and issue #73.
    at_rest_key        BYTEA    NOT NULL,

    -- Null unless the upload is password protected. Stored unencrypted because
    -- a client must know them before it can derive anything; they disclose only
    -- that a password exists.
    password_salt      BYTEA,
    argon2_memory_kib  BIGINT,
    argon2_iterations  BIGINT,
    argon2_parallelism BIGINT,

    size               BIGINT      NOT NULL,
    created_at         BIGINT      NOT NULL,

    -- Null means the upload never expires, which requires
    -- SENDAN_ALLOW_INFINITE_TTL to have been set when it was created.
    expires_at         BIGINT,

    -- Zero means no download limit.
    max_downloads      BIGINT  NOT NULL DEFAULT 0,
    download_count     BIGINT  NOT NULL DEFAULT 0,

    CHECK (size >= 0),
    CHECK (max_downloads >= 0),
    CHECK (download_count >= 0),
    -- A password is either fully specified or absent; a partial set would let
    -- a client derive with parameters the uploader never chose.
    CHECK (
        (password_salt IS NULL AND argon2_memory_kib IS NULL
            AND argon2_iterations IS NULL AND argon2_parallelism IS NULL)
        OR
        (password_salt IS NOT NULL AND argon2_memory_kib IS NOT NULL
            AND argon2_iterations IS NOT NULL AND argon2_parallelism IS NOT NULL)
    )
);

-- The reaper scans by deadline, so this is the only index that earns its cost.
CREATE INDEX uploads_expires_at ON uploads (expires_at) WHERE expires_at IS NOT NULL;

-- Exhausted uploads are found by comparing two columns, which no simple index
-- covers; this partial index at least narrows the scan to limited uploads.
CREATE INDEX uploads_max_downloads ON uploads (max_downloads) WHERE max_downloads > 0;
