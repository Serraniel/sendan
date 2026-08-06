// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// spool accumulates a chunked upload on local disk.
//
// Both backends use it, so a partial upload behaves identically whichever one
// is configured. The filesystem store then renames the spool into place; the
// object store uploads it and removes it.
//
// The name is derived from the identifier rather than random, because a resumed
// upload has to find what a previous request left behind.
type spool struct{ dir string }

func (s spool) path(id string) (string, error) {
	if err := validateID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, "."+id+".partial"), nil
}

// writeChunk appends r, refusing anything that does not continue where the
// stored bytes end.
func (s spool) writeChunk(ctx context.Context, id string, offset int64, r io.Reader) (int64, error) {
	name, err := s.path(id)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return 0, fmt.Errorf("blob: create directory: %w", err)
	}

	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // the path is built from a validated identifier
	if err != nil {
		return 0, fmt.Errorf("blob: open partial: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Checked against the open file rather than a separate stat, so the length
	// cannot change between the check and the write.
	info, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("blob: stat partial: %w", err)
	}
	if info.Size() != offset {
		return 0, fmt.Errorf("%w: offset %d, stored %d", ErrOffset, offset, info.Size())
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, fmt.Errorf("blob: seek partial: %w", err)
	}

	n, err := io.Copy(f, &contextReader{ctx: ctx, r: r})
	if err != nil {
		// The bytes that arrived are kept. A client that resumes is told the
		// new length and continues from it; discarding them would make every
		// interruption restart the upload, which is what resumability exists to
		// avoid.
		return n, fmt.Errorf("blob: write chunk: %w", err)
	}
	if err := f.Sync(); err != nil {
		return n, fmt.Errorf("blob: sync partial: %w", err)
	}
	return n, nil
}

func (s spool) length(id string) (int64, error) {
	name, err := s.path(id)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(name)
	if errors.Is(err, os.ErrNotExist) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("blob: stat partial: %w", err)
	}
	return info.Size(), nil
}

// open returns the spooled bytes for reading, so a backend can upload them.
func (s spool) open(id string) (*os.File, error) {
	name, err := s.path(id)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(name) //nolint:gosec // the path is built from a validated identifier
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("blob: open partial: %w", err)
	}
	return f, nil
}

// remove discards a partial upload. A partial that was never finished is a
// leftover like any other, so this is called on deletion as well as on success.
func (s spool) remove(id string) error {
	name, err := s.path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blob: remove partial: %w", err)
	}
	return nil
}
