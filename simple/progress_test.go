// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package simple

import (
	"sync"
	"testing"
	"time"
)

func TestNewProgressTracker_InitialState(t *testing.T) {
	tracker := NewProgressTracker(42, "test-source", nil)
	p := tracker.GetProgress()

	if p.SourceID != 42 {
		t.Errorf("SourceID = %d, want 42", p.SourceID)
	}
	if p.SourceName != "test-source" {
		t.Errorf("SourceName = %q, want %q", p.SourceName, "test-source")
	}
	if p.Phase != PhaseScanning {
		t.Errorf("Phase = %q, want %q", p.Phase, PhaseScanning)
	}
	if p.ProcessedFiles != 0 {
		t.Errorf("ProcessedFiles = %d, want 0", p.ProcessedFiles)
	}
	if p.TotalFiles != 0 {
		t.Errorf("TotalFiles = %d, want 0", p.TotalFiles)
	}
	if p.NewFiles != 0 {
		t.Errorf("NewFiles = %d, want 0", p.NewFiles)
	}
	if p.ChangedFiles != 0 {
		t.Errorf("ChangedFiles = %d, want 0", p.ChangedFiles)
	}
	if p.UnchangedFiles != 0 {
		t.Errorf("UnchangedFiles = %d, want 0", p.UnchangedFiles)
	}
	if p.TotalBytes != 0 {
		t.Errorf("TotalBytes = %d, want 0", p.TotalBytes)
	}
	if p.ProcessedBytes != 0 {
		t.Errorf("ProcessedBytes = %d, want 0", p.ProcessedBytes)
	}
	if p.UploadedBytes != 0 {
		t.Errorf("UploadedBytes = %d, want 0", p.UploadedBytes)
	}
	if p.CurrentFile != "" {
		t.Errorf("CurrentFile = %q, want empty", p.CurrentFile)
	}
	if p.BytesPerSecond != 0 {
		t.Errorf("BytesPerSecond = %f, want 0", p.BytesPerSecond)
	}
	if p.EstimatedEtaSec != 0 {
		t.Errorf("EstimatedEtaSec = %f, want 0", p.EstimatedEtaSec)
	}
}

func TestSetPhase_Transitions(t *testing.T) {
	var lastPhase Phase
	tracker := NewProgressTracker(1, "src", func(p Progress) {
		lastPhase = p.Phase
	})

	tracker.SetPhase(PhaseUploading)
	if lastPhase != PhaseUploading {
		t.Errorf("callback phase = %q, want %q", lastPhase, PhaseUploading)
	}

	tracker.SetPhase(PhaseComplete)
	if lastPhase != PhaseComplete {
		t.Errorf("callback phase = %q, want %q", lastPhase, PhaseComplete)
	}

	tracker.SetPhase(PhaseError)
	if lastPhase != PhaseError {
		t.Errorf("callback phase = %q, want %q", lastPhase, PhaseError)
	}

	p := tracker.GetProgress()
	if p.Phase != PhaseError {
		t.Errorf("final phase = %q, want %q", p.Phase, PhaseError)
	}
}

func TestSetPhase_ScanningResetsStartedAt(t *testing.T) {
	tracker := NewProgressTracker(1, "src", nil)

	tracker.SetPhase(PhaseUploading)
	time.Sleep(10 * time.Millisecond)
	tracker.SetPhase(PhaseScanning)

	p := tracker.GetProgress()
	if p.StartedAt.IsZero() {
		t.Error("StartedAt should be set when phase transitions to scanning")
	}
}

func TestSetTotal(t *testing.T) {
	var callbackCount int
	var lastProgress Progress
	tracker := NewProgressTracker(1, "src", func(p Progress) {
		callbackCount++
		lastProgress = p
	})

	tracker.SetTotal(100, 1<<30)

	if callbackCount != 1 {
		t.Errorf("callback called %d times, want 1", callbackCount)
	}
	if lastProgress.TotalFiles != 100 {
		t.Errorf("TotalFiles = %d, want 100", lastProgress.TotalFiles)
	}
	if lastProgress.TotalBytes != 1<<30 {
		t.Errorf("TotalBytes = %d, want %d", lastProgress.TotalBytes, 1<<30)
	}

	p := tracker.GetProgress()
	if p.TotalFiles != 100 {
		t.Errorf("GetProgress TotalFiles = %d, want 100", p.TotalFiles)
	}
	if p.TotalBytes != 1<<30 {
		t.Errorf("GetProgress TotalBytes = %d, want %d", p.TotalBytes, 1<<30)
	}
}

func TestFileProcessed_NewFile(t *testing.T) {
	var lastProgress Progress
	tracker := NewProgressTracker(1, "src", func(p Progress) {
		lastProgress = p
	})
	tracker.SetTotal(10, 10000)

	tracker.FileProcessed("file1.txt", 500, true, false)

	if lastProgress.NewFiles != 1 {
		t.Errorf("NewFiles = %d, want 1", lastProgress.NewFiles)
	}
	if lastProgress.UploadedBytes != 500 {
		t.Errorf("UploadedBytes = %d, want 500", lastProgress.UploadedBytes)
	}
	if lastProgress.ProcessedFiles != 1 {
		t.Errorf("ProcessedFiles = %d, want 1", lastProgress.ProcessedFiles)
	}
	if lastProgress.ProcessedBytes != 500 {
		t.Errorf("ProcessedBytes = %d, want 500", lastProgress.ProcessedBytes)
	}
	if lastProgress.CurrentFile != "file1.txt" {
		t.Errorf("CurrentFile = %q, want %q", lastProgress.CurrentFile, "file1.txt")
	}
	if lastProgress.ChangedFiles != 0 {
		t.Errorf("ChangedFiles = %d, want 0", lastProgress.ChangedFiles)
	}
	if lastProgress.UnchangedFiles != 0 {
		t.Errorf("UnchangedFiles = %d, want 0", lastProgress.UnchangedFiles)
	}
}

func TestFileProcessed_ChangedFile(t *testing.T) {
	var lastProgress Progress
	tracker := NewProgressTracker(1, "src", func(p Progress) {
		lastProgress = p
	})
	tracker.SetTotal(10, 10000)

	tracker.FileProcessed("file2.txt", 800, false, true)

	if lastProgress.ChangedFiles != 1 {
		t.Errorf("ChangedFiles = %d, want 1", lastProgress.ChangedFiles)
	}
	if lastProgress.UploadedBytes != 800 {
		t.Errorf("UploadedBytes = %d, want 800", lastProgress.UploadedBytes)
	}
	if lastProgress.NewFiles != 0 {
		t.Errorf("NewFiles = %d, want 0", lastProgress.NewFiles)
	}
	if lastProgress.UnchangedFiles != 0 {
		t.Errorf("UnchangedFiles = %d, want 0", lastProgress.UnchangedFiles)
	}
}

func TestFileProcessed_UnchangedFile(t *testing.T) {
	var lastProgress Progress
	tracker := NewProgressTracker(1, "src", func(p Progress) {
		lastProgress = p
	})
	tracker.SetTotal(10, 10000)

	tracker.FileProcessed("file3.txt", 300, false, false)

	if lastProgress.UnchangedFiles != 1 {
		t.Errorf("UnchangedFiles = %d, want 1", lastProgress.UnchangedFiles)
	}
	if lastProgress.UploadedBytes != 0 {
		t.Errorf("UploadedBytes = %d, want 0 (unchanged files should not add to UploadedBytes)", lastProgress.UploadedBytes)
	}
	if lastProgress.ProcessedBytes != 300 {
		t.Errorf("ProcessedBytes = %d, want 300", lastProgress.ProcessedBytes)
	}
	if lastProgress.NewFiles != 0 {
		t.Errorf("NewFiles = %d, want 0", lastProgress.NewFiles)
	}
	if lastProgress.ChangedFiles != 0 {
		t.Errorf("ChangedFiles = %d, want 0", lastProgress.ChangedFiles)
	}
}

func TestFileProcessed_CumulativeCounts(t *testing.T) {
	tracker := NewProgressTracker(1, "src", nil)
	tracker.SetTotal(100, 100000)

	tracker.FileProcessed("a.txt", 100, true, false)
	tracker.FileProcessed("b.txt", 200, false, true)
	tracker.FileProcessed("c.txt", 50, false, false)
	tracker.FileProcessed("d.txt", 150, true, false)
	tracker.FileProcessed("e.txt", 75, false, false)

	p := tracker.GetProgress()

	if p.ProcessedFiles != 5 {
		t.Errorf("ProcessedFiles = %d, want 5", p.ProcessedFiles)
	}
	if p.ProcessedBytes != 575 {
		t.Errorf("ProcessedBytes = %d, want 575", p.ProcessedBytes)
	}
	if p.NewFiles != 2 {
		t.Errorf("NewFiles = %d, want 2", p.NewFiles)
	}
	if p.ChangedFiles != 1 {
		t.Errorf("ChangedFiles = %d, want 1", p.ChangedFiles)
	}
	if p.UnchangedFiles != 2 {
		t.Errorf("UnchangedFiles = %d, want 2", p.UnchangedFiles)
	}
	if p.UploadedBytes != 450 {
		t.Errorf("UploadedBytes = %d, want 450 (100+200+150)", p.UploadedBytes)
	}
	if p.CurrentFile != "e.txt" {
		t.Errorf("CurrentFile = %q, want %q", p.CurrentFile, "e.txt")
	}
}

func TestGetProgress_ReturnsCopy(t *testing.T) {
	tracker := NewProgressTracker(1, "src", nil)
	tracker.SetTotal(10, 1000)
	tracker.FileProcessed("a.txt", 100, true, false)

	p1 := tracker.GetProgress()
	p1.NewFiles = 999
	p1.UploadedBytes = 99999

	p2 := tracker.GetProgress()
	if p2.NewFiles == 999 {
		t.Error("modifying returned Progress should not affect tracker state")
	}
	if p2.UploadedBytes == 99999 {
		t.Error("modifying returned Progress should not affect tracker state")
	}
}

func TestCallback_InvocationOnEachUpdate(t *testing.T) {
	var callbackCount int
	tracker := NewProgressTracker(1, "src", func(p Progress) {
		callbackCount++
	})

	tracker.SetPhase(PhaseUploading)
	tracker.SetTotal(10, 1000)
	tracker.FileProcessed("a.txt", 100, true, false)
	tracker.FileProcessed("b.txt", 200, false, true)
	tracker.SetPhase(PhaseComplete)

	wantCallbacks := 5
	if callbackCount != wantCallbacks {
		t.Errorf("callback invoked %d times, want %d", callbackCount, wantCallbacks)
	}
}

func TestCallback_NilCallbackDoesNotPanic(t *testing.T) {
	tracker := NewProgressTracker(1, "src", nil)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil callback caused panic: %v", r)
		}
	}()

	tracker.SetPhase(PhaseUploading)
	tracker.SetTotal(10, 1000)
	tracker.FileProcessed("a.txt", 100, true, false)
}

func TestFileProcessed_ConcurrentAccess(t *testing.T) {
	tracker := NewProgressTracker(1, "src", func(p Progress) {})
	tracker.SetTotal(1000, 1000000)

	var wg sync.WaitGroup
	numGoroutines := 50
	filesPerGoroutine := 20

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < filesPerGoroutine; i++ {
				isNew := i%3 == 0
				isChanged := i%3 == 1
				tracker.FileProcessed("file", 10, isNew, isChanged)
			}
		}(g)
	}
	wg.Wait()

	p := tracker.GetProgress()
	totalExpected := numGoroutines * filesPerGoroutine
	if p.ProcessedFiles != totalExpected {
		t.Errorf("ProcessedFiles = %d, want %d", p.ProcessedFiles, totalExpected)
	}
}

func TestFileProcessed_ETAAndThroughput(t *testing.T) {
	tracker := NewProgressTracker(1, "src", func(p Progress) {})
	tracker.SetTotal(100, 10000)

	tracker.FileProcessed("a.txt", 1000, true, false)
	time.Sleep(2 * time.Millisecond)
	tracker.FileProcessed("b.txt", 1000, true, false)

	p := tracker.GetProgress()
	if p.BytesPerSecond <= 0 {
		t.Errorf("BytesPerSecond = %f, want > 0 after processing files", p.BytesPerSecond)
	}

	remaining := p.TotalBytes - p.ProcessedBytes
	if remaining > 0 && p.BytesPerSecond > 0 {
		if p.EstimatedEtaSec <= 0 {
			t.Errorf("EstimatedEtaSec = %f, want > 0 when remaining bytes exist", p.EstimatedEtaSec)
		}
	}
}

func TestFileProcessed_ZeroElapsedNoDivisionByZero(t *testing.T) {
	tracker := NewProgressTracker(1, "src", func(p Progress) {})
	tracker.SetTotal(100, 10000)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic on rapid FileProcessed: %v", r)
		}
	}()

	tracker.FileProcessed("a.txt", 100, true, false)
}
