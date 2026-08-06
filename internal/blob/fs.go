// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// idPattern is the exact shape of a blob identifier: base64url of a 16-byte
// file identifier, so 22 characters from an alphabet with no path separators
// and no dot.
const idLength = 22

// FS stores blobs as files beneath a root directory.
type FS struct {
	root string
}

var _ Store = (*FS)(nil)

// NewFS returns a filesystem-backed [Store] rooted at dir, creating it if
// necessary.
func NewFS(dir string) (*FS, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("blob: resolve root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("blob: create root: %w", err)
	}
	return &FS{root: abs}, nil
}

// validateID rejects anything that is not exactly a base64url identifier.
//
// Identifiers arrive from request paths. Allowing a separator, a dot, or an
// unexpected length would let a crafted value address a file outside the
// storage root, so this is an allowlist rather than an attempt to strip
// dangerous sequences.
func validateID(id string) error {
	if len(id) != idLength {
		return fmt.Errorf("%w: length %d, want %d", ErrInvalidID, len(id), idLength)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return fmt.Errorf("%w: character %q at offset %d", ErrInvalidID, c, i)
		}
	}
	return nil
}

// path shards on the first four characters, so a large instance does not end
// up with millions of entries in one directory.
func (s *FS) path(id string) (string, error) {
	if err := validateID(id); err != nil {
		return "", err
	}
	return filepath.Join(s.root, id[0:2], id[2:4], id), nil
}

// Put writes to a temporary file and renames it into place, so a reader never
// observes a partial blob and a failed write leaves nothing behind.
func (s *FS) Put(ctx context.Context, id string, r io.Reader) (int64, error) {
	final, err := s.path(id)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return 0, fmt.Errorf("blob: create directory: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(final), "."+id+".*.partial")
	if err != nil {
		return 0, fmt.Errorf("blob: create temporary file: %w", err)
	}
	tmpName := tmp.Name()

	// Any path out of this function other than a successful rename must remove
	// the temporary file, including cancellation and a panic.
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	n, err := io.Copy(tmp, &contextReader{ctx: ctx, r: r})
	if err != nil {
		return 0, fmt.Errorf("blob: write: %w", err)
	}
	// Durability before the rename, so a crash cannot leave a named blob whose
	// contents were never flushed.
	if err := tmp.Sync(); err != nil {
		return 0, fmt.Errorf("blob: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("blob: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return 0, fmt.Errorf("blob: set permissions: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return 0, fmt.Errorf("blob: commit: %w", err)
	}
	committed = true
	return n, nil
}

// Open returns the blob positioned at its start.
func (s *FS) Open(_ context.Context, id string) (io.ReadSeekCloser, error) {
	path, err := s.path(id)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // path is derived from a validated identifier
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("blob: open: %w", err)
	}
	return f, nil
}

// Delete removes the blob and prunes the shard directories it leaves empty, so
// an instance that has expired everything does not keep an empty tree
// describing how many uploads it once held.
func (s *FS) Delete(_ context.Context, id string) error {
	path, err := s.path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("blob: delete: %w", err)
	}

	// A partial upload that was never finished is a leftover like any other,
	// and it holds the same ciphertext the finished blob would have.
	sp, err := s.spool(id)
	if err != nil {
		return err
	}
	if err := sp.remove(id); err != nil {
		return err
	}

	dir := filepath.Dir(path)
	for range 2 {
		if dir == s.root {
			break
		}
		// Fails harmlessly while the directory still holds other blobs.
		if err := os.Remove(dir); err != nil {
			break
		}
		dir = filepath.Dir(dir)
	}
	return nil
}

// contextReader aborts a copy when the request is cancelled, so an abandoned
// upload stops consuming disk immediately rather than running to completion.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// spool returns the partial-upload area, which for the filesystem store sits
// beside the blob so that finishing is a rename rather than a copy.
func (s *FS) spool(id string) (spool, error) {
	final, err := s.path(id)
	if err != nil {
		return spool{}, err
	}
	return spool{dir: filepath.Dir(final)}, nil
}

// WriteChunk appends to a partial upload.
func (s *FS) WriteChunk(ctx context.Context, id string, offset int64, r io.Reader) (int64, error) {
	sp, err := s.spool(id)
	if err != nil {
		return 0, err
	}
	return sp.writeChunk(ctx, id, offset, r)
}

// Length reports how many bytes of a partial upload are stored.
func (s *FS) Length(_ context.Context, id string) (int64, error) {
	sp, err := s.spool(id)
	if err != nil {
		return 0, err
	}
	return sp.length(id)
}

// Finish renames the partial upload into place, which is what makes it
// readable. A rename is atomic, so a reader never observes a half-written blob.
func (s *FS) Finish(_ context.Context, id string) error {
	sp, err := s.spool(id)
	if err != nil {
		return err
	}
	partial, err := sp.path(id)
	if err != nil {
		return err
	}
	final, err := s.path(id)
	if err != nil {
		return err
	}
	if _, err := os.Stat(partial); errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err := os.Rename(partial, final); err != nil {
		return fmt.Errorf("blob: finish: %w", err)
	}
	return nil
}
