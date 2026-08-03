-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- See the SQLite migration of the same name for why the download counter
-- accounts by volume rather than by request or by completion.
ALTER TABLE uploads ADD COLUMN bytes_served BIGINT NOT NULL DEFAULT 0;
