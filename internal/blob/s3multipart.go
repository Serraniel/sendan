// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	minio "github.com/minio/minio-go/v7"
)

// partSize is the smallest part a multipart upload accepts, except for the last
// one, which may be any size.
//
// Objects cannot be appended to, so a chunked upload has to accumulate
// somewhere. Accumulating in the object store rather than on local disk is what
// lets a resumed chunk reach a different replica than the one before it, and
// removes the requirement for scratch space the size of the upload.
const partSize = 5 << 20

// tailKey is where the bytes below a part boundary wait.
//
// A tus client chunks however it likes, and S3 will not accept a part under
// five mebibytes. Whatever is left over after filling parts is held as its own
// object until enough arrives to complete a part, or until the upload finishes
// and it becomes the last part - the one size limit does not apply to.
//
// Identifiers cannot contain a dot, so this cannot collide with a blob.
func tailKey(key string) string { return key + ".part" }

// s3state is what an object store knows about a partial upload.
//
// Read back rather than remembered. Nothing about a partial upload lives in
// this process, which is the point: an instance that restarts, or a second
// replica behind a load balancer, sees exactly what the first one left.
type s3state struct {
	uploadID string
	parts    []minio.ObjectPart
	stored   int64 // bytes in completed parts
	tail     int64 // bytes in the trailing incomplete part
}

func (st *s3state) length() int64 { return st.stored + st.tail }

// state gathers what is stored for a key.
func (s *S3) state(ctx context.Context, key string) (*s3state, error) {
	uploadID, err := s.uploadIDFor(ctx, key)
	if err != nil {
		return nil, err
	}
	st := &s3state{uploadID: uploadID}
	if uploadID == "" {
		return st, nil
	}

	// Paged, because an upload at the maximum size has more parts than one
	// response returns and a truncated list would understate the offset - which
	// a client would then resume from, overwriting what is already there.
	for marker := 0; ; {
		res, err := s.core.ListObjectParts(ctx, s.bucket, key, uploadID, marker, 1000)
		if err != nil {
			return nil, fmt.Errorf("blob: list parts: %w", err)
		}
		st.parts = append(st.parts, res.ObjectParts...)
		if !res.IsTruncated {
			break
		}
		marker = res.NextPartNumberMarker
	}

	// Parts are numbered from one as they are written, so a complete listing is
	// 1..N in order. S3 promises ascending order and every implementation
	// tested returns it that way, which is why no test here can reach the sort:
	// it is insurance against an implementation that does not, where the cost
	// of being wrong is an object assembled in the wrong order rather than an
	// error.
	sort.Slice(st.parts, func(i, j int) bool { return st.parts[i].PartNumber < st.parts[j].PartNumber })

	for i, p := range st.parts {
		// A gap means a part is missing from the listing - a failed upload that
		// reported success, or a page of results lost. Completing anyway would
		// produce an object shorter than what was sent, which nobody would
		// notice until a recipient could not decrypt it.
		if p.PartNumber != i+1 {
			return nil, fmt.Errorf(
				"blob: the object store lists part %d where part %d should be, "+
					"so this upload cannot be completed without losing data",
				p.PartNumber, i+1)
		}
		st.stored += p.Size
	}

	info, err := s.client.StatObject(ctx, s.bucket, tailKey(key), minio.StatObjectOptions{})
	switch {
	case err == nil:
		st.tail = info.Size
	case !isNotFound(err):
		return nil, fmt.Errorf("blob: stat partial: %w", err)
	}
	return st, nil
}

// uploadIDFor finds the multipart upload in progress for a key, or "".
//
// More than one can exist if a previous attempt was interrupted between
// starting an upload and writing to it. The most recent wins, and Delete aborts
// every one, so a leaked attempt costs storage until the upload is reaped
// rather than confusing the next write.
func (s *S3) uploadIDFor(ctx context.Context, key string) (string, error) {
	found, err := s.uploadsFor(ctx, key)
	if err != nil || len(found) == 0 {
		return "", err
	}
	newest := found[0]
	for _, u := range found[1:] {
		if u.Initiated.After(newest.Initiated) {
			newest = u
		}
	}
	return newest.UploadID, nil
}

func (s *S3) uploadsFor(ctx context.Context, key string) ([]minio.ObjectMultipartInfo, error) {
	var found []minio.ObjectMultipartInfo
	keyMarker, idMarker := "", ""
	for {
		res, err := s.core.ListMultipartUploads(ctx, s.bucket, key, keyMarker, idMarker, "", 1000)
		if err != nil {
			return nil, fmt.Errorf("blob: list uploads: %w", err)
		}
		for _, u := range res.Uploads {
			// A prefix search, so it also returns the tail object's key and
			// anything else beginning with this one.
			if u.Key == key {
				found = append(found, u)
			}
		}
		if !res.IsTruncated {
			return found, nil
		}
		keyMarker, idMarker = res.NextKeyMarker, res.NextUploadIDMarker
	}
}

// writeChunk appends r to the partial upload under key.
//
// Bytes below a part boundary are carried in the tail object, so an upload sent
// in chunks smaller than a part still progresses. Without that, a client
// sending one mebibyte at a time would never fill a part and the offset would
// never move.
func (s *S3) writeChunk(ctx context.Context, key string, offset int64, r io.Reader) (int64, error) {
	st, err := s.state(ctx, key)
	if err != nil {
		return 0, err
	}
	if offset != st.length() {
		return 0, ErrOffset
	}

	if st.uploadID == "" {
		if st.uploadID, err = s.core.NewMultipartUpload(ctx, s.bucket, key,
			minio.PutObjectOptions{ContentType: "application/octet-stream"}); err != nil {
			return 0, fmt.Errorf("blob: start upload: %w", err)
		}
	}

	// The tail is read back and put in front of the incoming bytes, so what
	// gets uploaded is a whole part rather than two fragments.
	var head []byte
	if st.tail > 0 {
		if head, err = s.readTail(ctx, key); err != nil {
			return 0, err
		}
	}

	next := len(st.parts) + 1
	buf := make([]byte, partSize)
	source := io.MultiReader(bytes.NewReader(head), r)

	// Counted from what the caller supplied, not from what was uploaded: the
	// tail was already accounted for by the request that stored it, and
	// reporting it twice would move the offset past what the client sent.
	carried := int64(len(head))
	var read int64

	for {
		n, err := io.ReadFull(source, buf)
		read += int64(n)

		if n == len(buf) {
			if _, err := s.core.PutObjectPart(ctx, s.bucket, key, st.uploadID, next,
				bytes.NewReader(buf), int64(n), minio.PutObjectPartOptions{}); err != nil {
				return max(0, read-carried), fmt.Errorf("blob: put part: %w", err)
			}
			next++
			continue
		}

		// Short read: the source is exhausted, and whatever is left becomes the
		// tail. Any other error is reported after storing what did arrive, so
		// an interrupted chunk keeps its bytes and the client resumes from
		// where they end.
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			if putErr := s.putTail(ctx, key, buf[:n]); putErr != nil {
				return max(0, read-carried), putErr
			}
			return max(0, read-carried), fmt.Errorf("blob: write chunk: %w", err)
		}
		if err := s.putTail(ctx, key, buf[:n]); err != nil {
			return max(0, read-carried), err
		}
		return read - carried, nil
	}
}

// putTail replaces the trailing incomplete part, removing it when empty.
func (s *S3) putTail(ctx context.Context, key string, b []byte) error {
	if len(b) == 0 {
		return s.removeTail(ctx, key)
	}
	if _, err := s.client.PutObject(ctx, s.bucket, tailKey(key), bytes.NewReader(b), int64(len(b)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"}); err != nil {
		return fmt.Errorf("blob: put partial: %w", err)
	}
	return nil
}

func (s *S3) readTail(ctx context.Context, key string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, tailKey(key), minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("blob: open partial: %w", err)
	}
	defer func() { _ = obj.Close() }()

	b, err := io.ReadAll(obj)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("blob: read partial: %w", err)
	}
	return b, nil
}

func (s *S3) removeTail(ctx context.Context, key string) error {
	err := s.client.RemoveObject(ctx, s.bucket, tailKey(key), minio.RemoveObjectOptions{})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("blob: remove partial: %w", err)
	}
	return nil
}

// finish completes the multipart upload, making the object readable.
//
// The tail becomes the last part, which is the one part no size limit applies
// to. Completion is atomic from a reader's point of view: there is no moment at
// which half an object can be fetched.
func (s *S3) finish(ctx context.Context, key string) error {
	st, err := s.state(ctx, key)
	if err != nil {
		return err
	}
	if st.uploadID == "" {
		return ErrNotFound
	}

	// An upload of nothing has no parts, and a multipart upload with no parts
	// cannot be completed. It is still a blob somebody asked to store.
	if st.stored == 0 && st.tail == 0 {
		if err := s.core.AbortMultipartUpload(ctx, s.bucket, key, st.uploadID); err != nil {
			return fmt.Errorf("blob: abort empty upload: %w", err)
		}
		_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(nil), 0,
			minio.PutObjectOptions{ContentType: "application/octet-stream"})
		if err != nil {
			return fmt.Errorf("blob: finish empty: %w", err)
		}
		return nil
	}

	complete := make([]minio.CompletePart, 0, len(st.parts)+1)
	for _, p := range st.parts {
		complete = append(complete, minio.CompletePart{PartNumber: p.PartNumber, ETag: p.ETag})
	}

	if st.tail > 0 {
		tail, err := s.readTail(ctx, key)
		if err != nil {
			return err
		}
		part, err := s.core.PutObjectPart(ctx, s.bucket, key, st.uploadID, len(st.parts)+1,
			bytes.NewReader(tail), int64(len(tail)), minio.PutObjectPartOptions{})
		if err != nil {
			return fmt.Errorf("blob: put last part: %w", err)
		}
		complete = append(complete, minio.CompletePart{PartNumber: part.PartNumber, ETag: part.ETag})
	}

	if _, err := s.core.CompleteMultipartUpload(ctx, s.bucket, key, st.uploadID, complete,
		minio.PutObjectOptions{}); err != nil {
		return fmt.Errorf("blob: finish: %w", err)
	}

	// Only once the object exists. A crash between the two leaves an orphaned
	// tail object, which Delete removes; the reverse would lose bytes that the
	// completed object already contains anyway.
	return s.removeTail(ctx, key)
}

// discardPartial aborts every multipart upload for a key and removes the tail.
//
// An abandoned multipart upload holds storage exactly as an abandoned spool
// file held disk, so this is reached whenever a blob is deleted - including by
// the reaper, which is what collects uploads that were never finished.
func (s *S3) discardPartial(ctx context.Context, key string) error {
	uploads, err := s.uploadsFor(ctx, key)
	if err != nil {
		return err
	}
	for _, u := range uploads {
		if err := s.core.AbortMultipartUpload(ctx, s.bucket, key, u.UploadID); err != nil && !isNotFound(err) {
			return fmt.Errorf("blob: abort upload: %w", err)
		}
	}
	return s.removeTail(ctx, key)
}
