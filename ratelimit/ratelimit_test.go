// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package ratelimit

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestLimiterZeroRateIsNoOp(t *testing.T) {
	l := NewLimiter(0)
	defer l.Stop()
	if err := l.WaitN(context.Background(), 1<<20); err != nil {
		t.Fatalf("zero-rate limiter should not block: %v", err)
	}
}

func TestLimiterAllowsBytesUpToBucket(t *testing.T) {
	// 1 KiB/s limiter starts with a full 1 KiB bucket, so the first 1 KiB
	// must complete without blocking.
	l := NewLimiter(1024)
	defer l.Stop()
	start := time.Now()
	if err := l.WaitN(context.Background(), 1024); err != nil {
		t.Fatalf("WaitN: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("initial bucket should not block: elapsed %v", elapsed)
	}
}

func TestLimiterContextCancel(t *testing.T) {
	l := NewLimiter(1) // 1 byte/s, bucket holds at most 1 byte
	defer l.Stop()
	// Drain initial bucket.
	if err := l.WaitN(context.Background(), 1); err != nil {
		t.Fatalf("drain: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := l.WaitN(ctx, 1)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestLimiterSetRate(t *testing.T) {
	l := NewLimiter(1)
	defer l.Stop()
	// Drain initial bucket.
	if err := l.WaitN(context.Background(), 1); err != nil {
		t.Fatalf("drain: %v", err)
	}
	// Bump rate; bucket cap should grow and refill on next tick.
	l.SetRate(1 << 20)
	// Give refill goroutine time to run.
	time.Sleep(200 * time.Millisecond)
	if err := l.WaitN(context.Background(), 1024); err != nil {
		t.Fatalf("WaitN after SetRate: %v", err)
	}
}

func TestLimiterStopIsIdempotent(t *testing.T) {
	l := NewLimiter(1024)
	l.Stop()
	// Stopping twice must not panic on close(stopCh).
	l.Stop()
}

func TestLimiterStopOnZeroRate(t *testing.T) {
	// Zero-rate limiter has a nil ticker; Stop must handle that.
	l := NewLimiter(0)
	l.Stop()
}

func TestWriterThrottlesLargeWrite(t *testing.T) {
	l := NewLimiter(1 << 10) // 1 KiB/s
	defer l.Stop()
	var sink bytes.Buffer
	w := NewWriter(&sink, l)
	// Drain initial bucket first so subsequent writes block.
	if err := l.WaitN(context.Background(), 1<<10); err != nil {
		t.Fatalf("drain: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = w.Write(make([]byte, 1<<10))
		close(done)
	}()
	select {
	case <-done:
		// Write should not have completed instantly given an empty bucket.
		t.Fatal("write completed without throttling")
	case <-time.After(100 * time.Millisecond):
		// Throttling observed.
	}
}

func TestWriterReturnsUnderlyingError(t *testing.T) {
	l := NewLimiter(0)
	w := NewWriter(errWriter{io.ErrShortWrite}, l)
	_, err := w.Write([]byte("x"))
	if err != io.ErrShortWrite {
		t.Fatalf("expected ErrShortWrite, got %v", err)
	}
}

type errWriter struct{ err error }

func (w errWriter) Write(p []byte) (int, error) { return 0, w.err }

func TestReaderPassesThroughUnthrottled(t *testing.T) {
	l := NewLimiter(0)
	defer l.Stop()
	src := bytes.NewReader([]byte("hello"))
	r := NewReader(src, l)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}
