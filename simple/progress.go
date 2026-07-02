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

func (t *ProgressTracker) SetPhase(phase Phase) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.progress.Phase = phase
	if phase == PhaseScanning {
		t.progress.StartedAt = time.Now()
	}
	t.emit()
}

func (t *ProgressTracker) SetTotal(files int, bytes int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.progress.TotalFiles = files
	t.progress.TotalBytes = bytes
	t.emit()
}

func (t *ProgressTracker) FileProcessed(file string, size int64, isNew bool, isChanged bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.progress.ProcessedFiles++
	t.progress.ProcessedBytes += size
	t.progress.CurrentFile = file
	if isNew {
		t.progress.NewFiles++
		t.progress.UploadedBytes += size
	} else if isChanged {
		t.progress.ChangedFiles++
		t.progress.UploadedBytes += size
	} else {
		t.progress.UnchangedFiles++
	}
	elapsed := time.Since(t.start).Seconds()
	if elapsed > 0 {
		t.progress.BytesPerSecond = float64(t.progress.UploadedBytes) / elapsed
		remaining := t.progress.TotalBytes - t.progress.ProcessedBytes
		if t.progress.BytesPerSecond > 0 && remaining > 0 {
			t.progress.EstimatedEtaSec = float64(remaining) / t.progress.BytesPerSecond
		}
	}
	t.emit()
}

func (t *ProgressTracker) GetProgress() Progress {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.progress
}

func (t *ProgressTracker) emit() {
	if t.callback != nil {
		t.callback(t.progress)
	}
}
