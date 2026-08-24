// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package ratelimit

import (
	"bytes"
	"context"
	"io"
	"sync"
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

// SetRate(0) means "no limit": a waiter blocked on an empty bucket with a
// Background context must be released, and subsequent calls must not block.
func TestLimiterSetRateZeroWakesWaiters(t *testing.T) {
	l := NewLimiter(1) // 1 byte/s
	defer l.Stop()
	// Drain the initial bucket so the next WaitN blocks.
	if err := l.WaitN(context.Background(), 1); err != nil {
		t.Fatalf("drain: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- l.WaitN(context.Background(), 100)
	}()
	// Give the waiter time to actually block on the empty bucket.
	select {
	case err := <-done:
		t.Fatalf("WaitN returned before SetRate(0): %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	l.SetRate(0)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitN after SetRate(0): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitN still blocked after SetRate(0)")
	}
	// New calls at zero rate must not block either.
	if err := l.WaitN(context.Background(), 1<<20); err != nil {
		t.Fatalf("WaitN with zero rate: %v", err)
	}
}

// Exercises the WaitN/SetRate race surface: waiters read the rate while
// other goroutines flap it. Run with -race to catch regressions of the
// unsynchronized bytesPerSecond access.
func TestLimiterConcurrentSetRateAndWait(t *testing.T) {
	l := NewLimiter(1024)
	defer l.Stop()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				l.SetRate(int64(1024 * (i + 1)))
				l.SetRate(0)
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for j := 0; j < 50; j++ {
				if err := l.WaitN(ctx, 10); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestLimiterStopOnZeroRate(t *testing.T) {
	// Zero-rate limiter has a nil ticker; Stop must handle that.
	l := NewLimiter(0)
	l.Stop()
}

// TestLimiterLowRateRefillsAfterDrain pins the fractional-token fix: at
// rates where rate/10 truncates to zero (1..9 bytes/s), the integer
// refill `bucket += rate / 10` never added anything, so a drained bucket
// stayed empty forever. The fractional accumulator must eventually
// produce new tokens.
func TestLimiterLowRateRefillsAfterDrain(t *testing.T) {
	l := NewLimiter(5) // 5 bytes/s → 0.5 tokens per 100ms tick
	defer l.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := l.WaitN(ctx, 5); err != nil {
		t.Fatalf("drain: %v", err)
	}
	// 400ms ≈ 4 ticks × 0.5 tokens = 2 tokens.
	time.Sleep(400 * time.Millisecond)
	if err := l.WaitN(ctx, 1); err != nil {
		t.Fatalf("WaitN after fractional refill: %v — low-rate limiter stalled forever", err)
	}
}

// TestLimiterSingleBytePerSecondRefills is the extreme low-rate case: at
// 1 byte/s each tick adds 0.1 tokens, so a full token needs ~1s.
func TestLimiterSingleBytePerSecondRefills(t *testing.T) {
	l := NewLimiter(1)
	defer l.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := l.WaitN(ctx, 1); err != nil {
		t.Fatalf("drain: %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	if err := l.WaitN(ctx, 1); err != nil {
		t.Fatalf("WaitN(1 byte/s) after 1.2s: %v — limiter stalled forever", err)
	}
}

// TestLimiterZeroRateThenEnable pins the dynamic-enable lifecycle: a
// limiter created with NewLimiter(0) has no refill loop, so SetRate with a
// positive value must start one (with a full bucket) — otherwise WaitN
// blocks forever on an eternally empty bucket.
func TestLimiterZeroRateThenEnable(t *testing.T) {
	l := NewLimiter(0)
	l.SetRate(1024)
	defer l.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- l.WaitN(ctx, 1024) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitN after dynamic enable: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("WaitN blocked forever after NewLimiter(0)+SetRate(positive)")
	}
}

// TestLimiterStoppedIgnoresSetRate verifies that a stopped limiter stays
// inert: SetRate after Stop must be ignored entirely. If the rate were
// applied without a refill loop (or with the bucket shrunk to the new
// burst cap), waiters would block forever on an empty bucket.
func TestLimiterStoppedIgnoresSetRate(t *testing.T) {
	l := NewLimiter(1000) // full 1000-token bucket
	l.Stop()
	l.SetRate(100) // must be ignored: rate stays 1000, bucket stays full

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.WaitN(ctx, 1000) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitN on stopped limiter: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SetRate after Stop took effect — stopped limiter must be inert")
	}
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
