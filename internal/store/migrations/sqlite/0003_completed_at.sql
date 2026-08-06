-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- An upload exists before it is complete.
--
-- Chunks are encrypted with the row's at-rest key as they arrive, so the row
-- has to exist from the moment an upload is created rather than from the moment
-- it finishes. That leaves a window in which a row describes content that is
-- only partly written, and serving it would hand a recipient a file that
-- decrypts to nothing past the point the uploader stopped.
--
-- NULL means the upload is still being written. Liveness requires a value, so
-- an incomplete upload is unreachable by exactly the mechanism that already
-- makes an expired one unreachable, rather than by a second rule somewhere
-- else.
ALTER TABLE uploads ADD COLUMN completed_at INTEGER;

-- Rows that predate this migration were only ever created complete, so dating
-- them by their creation is accurate rather than a guess.
UPDATE uploads SET completed_at = created_at WHERE completed_at IS NULL;
