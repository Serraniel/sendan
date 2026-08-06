-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- See the SQLite migration of the same name for why an incomplete upload needs
-- to be distinguishable from a complete one.
ALTER TABLE uploads ADD COLUMN completed_at BIGINT;

UPDATE uploads SET completed_at = created_at WHERE completed_at IS NULL;
