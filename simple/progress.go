// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"sync"
	"time"
)

type Phase string

const (
	PhaseScanning  Phase = "scanning"
	PhaseUploading Phase = "uploading"
	PhaseComplete  Phase = "complete"
	PhaseError     Phase = "error"
)

type Progress struct {
	SourceID        int64     `json:"sourceId"`
	SourceName      string    `json:"sourceName"`
	Phase           Phase     `json:"phase"`
	TotalFiles      int       `json:"totalFiles"`
	ProcessedFiles  int       `json:"processedFiles"`
	TotalBytes      int64     `json:"totalBytes"`
	ProcessedBytes  int64     `json:"processedBytes"`
	NewFiles        int       `json:"newFiles"`
	ChangedFiles    int       `json:"changedFiles"`
	UnchangedFiles  int       `json:"unchangedFiles"`
	UploadedBytes   int64     `json:"uploadedBytes"`
	CurrentFile     string    `json:"currentFile"`
	BytesPerSecond  float64   `json:"bytesPerSecond"`
	StartedAt       time.Time `json:"startedAt"`
	EstimatedEtaSec float64   `json:"estimatedEtaSec"`
}

type ProgressCallback func(progress Progress)

type ProgressTracker struct {
	mu       sync.Mutex
	progress Progress
	callback ProgressCallback
	start    time.Time
	// cbMu serializes callback invocations (preserving the pre-refactor
	// guarantee that callbacks never run concurrently). It is only ever
	// acquired AFTER mu has been released, so a callback that calls back
	// into GetProgress no longer deadlocks, and a slow callback stalls
	// neither workers updating state nor GetProgress readers.
	cbMu sync.Mutex
}

func NewProgressTracker(sourceID int64, sourceName string, cb ProgressCallback) *ProgressTracker {
	return &ProgressTracker{
		progress: Progress{
			SourceID:   sourceID,
			SourceName: sourceName,
			Phase:      PhaseScanning,
		},
		callback: cb,
		start:    time.Now(),
	}
}

// update mutates the tracked state under mu, snapshots it, then invokes
// the callback with the snapshot AFTER releasing mu. Progress contains no
// references, so the snapshot is a deep-enough copy.
func (t *ProgressTracker) update(fn func(p *Progress)) {
	t.mu.Lock()
	fn(&t.progress)
	snapshot, cb := t.progress, t.callback
	t.mu.Unlock()
	if cb != nil {
		t.cbMu.Lock()
		cb(snapshot)
		t.cbMu.Unlock()
	}
}

func (t *ProgressTracker) SetPhase(phase Phase) {
	t.update(func(p *Progress) {
		p.Phase = phase
		if phase == PhaseScanning {
			p.StartedAt = time.Now()
		}
	})
}

func (t *ProgressTracker) SetTotal(files int, bytes int64) {
	t.update(func(p *Progress) {
		p.TotalFiles = files
		p.TotalBytes = bytes
	})
}

func (t *ProgressTracker) FileProcessed(file string, size int64, isNew bool, isChanged bool) {
	t.update(func(p *Progress) {
		p.ProcessedFiles++
		p.ProcessedBytes += size
		p.CurrentFile = file
		if isNew {
			p.NewFiles++
			p.UploadedBytes += size
		} else if isChanged {
			p.ChangedFiles++
			p.UploadedBytes += size
		} else {
			p.UnchangedFiles++
		}
		elapsed := time.Since(t.start).Seconds()
		if elapsed > 0 {
			p.BytesPerSecond = float64(p.UploadedBytes) / elapsed
			remaining := p.TotalBytes - p.ProcessedBytes
			if p.BytesPerSecond > 0 && remaining > 0 {
				p.EstimatedEtaSec = float64(remaining) / p.BytesPerSecond
			}
		}
	})
}

func (t *ProgressTracker) GetProgress() Progress {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.progress
}
