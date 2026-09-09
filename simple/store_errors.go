// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Blob store error taxonomy. Store implementations should classify
// failures into these sentinels so callers can distinguish "blob missing"
// (retryable, e.g. re-upload) from "store broken" (auth, permission,
// transient outage) instead of treating every error identically.
//
// Notably, a remote Exists/Put failure must NOT be classified as
// ErrBlobNotFound: authentication failure, network outage, and
// permission errors all look like "missing" to a naive caller and lead
// to masked outages and massive re-uploads.
var (
	// ErrBlobNotFound means the requested blob does not exist in the
	// store. Only classification for a confirmed absence.
	ErrBlobNotFound = errors.New("blob not found")
	// ErrPermissionDenied means the store refused access (filesystem
	// permissions, cloud IAM, auth).
	ErrPermissionDenied = errors.New("blob store permission denied")
	// ErrTransientFailure means the store failed temporarily (network
	// interruption, server 5xx, throttling) and the operation may be
	// retried.
	ErrTransientFailure = errors.New("transient blob store failure")
	// ErrStoreClosed means the store was closed before the call.
	ErrStoreClosed = errors.New("blob store is closed")
)

// ClassifyPathError maps a filesystem error from a blob path operation
// onto the taxonomy. The returned error wraps BOTH the sentinel and the
// original error, so errors.Is works for ErrBlobNotFound /
// ErrPermissionDenied as well as for fs.ErrNotExist / fs.ErrPermission.
func ClassifyPathError(op, hash string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s blob %s: %w: %w", op, hash, ErrBlobNotFound, err)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s blob %s: %w: %w", op, hash, ErrPermissionDenied, err)
	default:
		return fmt.Errorf("%s blob %s: %w", op, hash, err)
	}
}

// ValidateBlobHash reports whether hash is a well-formed blob key
// (64-character hex SHA-256). Exported for out-of-tree store
// implementations that must share the local store's contract of
// rejecting malformed hashes with ErrInvalidHash.
func ValidateBlobHash(hash string) bool {
	return validateHash(hash)
}

// classifyOSError is a convenience wrapper matching the pre-taxonomy
// behavior of callers that used os.IsNotExist directly.
func classifyOSError(op, hash string, err error) error {
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) {
		return ClassifyPathError(op, hash, err)
	}
	return fmt.Errorf("%s blob %s: %w", op, hash, err)
}
