// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type Limiter struct {
	// bytesPerSecond is accessed atomically: WaitN reads it on every
	// iteration (including from callers that never take mu, e.g. Reader),
	// while SetRate writes it — a plain int64 was a data race. A value
	// <= 0 means "no limit" and WaitN never blocks.
	bytesPerSecond atomic.Int64
	bucket         int64
	maxBucket      int64
	mu             sync.Mutex
	ticker         *time.Ticker
	stopCh         chan struct{}
	stopOnce       sync.Once
}

func NewLimiter(bytesPerSecond int64) *Limiter {
	if bytesPerSecond <= 0 {
		return &Limiter{}
	}

	l := &Limiter{
		bucket:    bytesPerSecond,
		maxBucket: bytesPerSecond * 2,
		stopCh:    make(chan struct{}),
	}
	l.bytesPerSecond.Store(bytesPerSecond)

	l.ticker = time.NewTicker(100 * time.Millisecond)
	go l.refill()

	return l
}

func (l *Limiter) refill() {
	for {
		select {
		case <-l.ticker.C:
			if rate := l.bytesPerSecond.Load(); rate > 0 {
				l.mu.Lock()
				l.bucket += rate / 10
				if l.bucket > l.maxBucket {
					l.bucket = l.maxBucket
				}
				l.mu.Unlock()
			}
		case <-l.stopCh:
			return
		}
	}
}

func (l *Limiter) WaitN(ctx context.Context, n int) error {
	for n > 0 {
		// Re-check the rate on every iteration: SetRate(0) means "no
		// limit", so waiters blocked on an empty bucket must observe it
		// and return instead of sleeping forever when ctx is Background.
		// The polling below bounds the wakeup latency to ~50ms.
		if l.bytesPerSecond.Load() <= 0 {
			return nil
		}
		l.mu.Lock()
		available := int(l.bucket)
		if available > 0 {
			if available > n {
				available = n
			}
			l.bucket -= int64(available)
			n -= available
			l.mu.Unlock()
			if n > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(50 * time.Millisecond):
				}
			}
			continue
		}
		l.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}

	return nil
}

func (l *Limiter) SetRate(bytesPerSecond int64) {
	l.bytesPerSecond.Store(bytesPerSecond)
	if bytesPerSecond > 0 {
		l.mu.Lock()
		l.maxBucket = bytesPerSecond * 2
		if l.bucket > l.maxBucket {
			l.bucket = l.maxBucket
		}
		l.mu.Unlock()
	}
}

func (l *Limiter) Stop() {
	l.stopOnce.Do(func() {
		if l.ticker != nil {
			l.ticker.Stop()
			close(l.stopCh)
		}
	})
}

type Reader struct {
	r interface {
		Read(p []byte) (n int, err error)
	}
	limiter *Limiter
}

func NewReader(r interface {
	Read(p []byte) (n int, err error)
}, limiter *Limiter) *Reader {
	return &Reader{r: r, limiter: limiter}
}

func (r *Reader) Read(p []byte) (n int, err error) {
	// io.Reader has no context parameter. Use ReadContext when you need
	// cancellation propagation.
	n, err = r.r.Read(p)
	if n > 0 && r.limiter != nil {
		if waitErr := r.limiter.WaitN(context.Background(), n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

// ReadContext reads through the limiter, honoring ctx cancellation while
// waiting for tokens. Callers holding a ctx should prefer this over Read.
func (r *Reader) ReadContext(ctx context.Context, p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	if n > 0 && r.limiter != nil {
		if waitErr := r.limiter.WaitN(ctx, n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

type Writer struct {
	w interface {
		Write(p []byte) (n int, err error)
	}
	limiter *Limiter
}

func NewWriter(w interface {
	Write(p []byte) (n int, err error)
}, limiter *Limiter) *Writer {
	return &Writer{w: w, limiter: limiter}
}

func (w *Writer) Write(p []byte) (n int, err error) {
	// io.Writer has no context parameter. Use WriteContext when you need
	// cancellation propagation (e.g. backing up under a deadline).
	return w.WriteContext(context.Background(), p)
}

// WriteContext writes p through the limiter, honoring ctx cancellation
// while waiting for tokens. Callers that already hold a ctx (e.g. a backup
// pipeline) should prefer this over Write so a cancelled backup does not
// block waiting for the rate limiter to refill.
func (w *Writer) WriteContext(ctx context.Context, p []byte) (n int, err error) {
	if w.limiter != nil {
		if waitErr := w.limiter.WaitN(ctx, len(p)); waitErr != nil {
			return 0, waitErr
		}
	}
	return w.w.Write(p)
}
