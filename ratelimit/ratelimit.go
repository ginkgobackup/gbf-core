// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Ginkgo Backup

package ratelimit

import (
	"context"
	"sync"
	"time"
)

type Limiter struct {
	bytesPerSecond int64
	bucket         int64
	maxBucket      int64
	mu             sync.Mutex
	ticker         *time.Ticker
	stopCh         chan struct{}
	stopOnce       sync.Once
}

func NewLimiter(bytesPerSecond int64) *Limiter {
	if bytesPerSecond <= 0 {
		return &Limiter{bytesPerSecond: 0}
	}

	l := &Limiter{
		bytesPerSecond: bytesPerSecond,
		bucket:         bytesPerSecond,
		maxBucket:      bytesPerSecond * 2,
		stopCh:         make(chan struct{}),
	}

	l.ticker = time.NewTicker(100 * time.Millisecond)
	go l.refill()

	return l
}

func (l *Limiter) refill() {
	for {
		select {
		case <-l.ticker.C:
			l.mu.Lock()
			if l.bytesPerSecond > 0 {
				increment := l.bytesPerSecond / 10
				l.bucket += increment
				if l.bucket > l.maxBucket {
					l.bucket = l.maxBucket
				}
			}
			l.mu.Unlock()
		case <-l.stopCh:
			return
		}
	}
}

func (l *Limiter) WaitN(ctx context.Context, n int) error {
	if l.bytesPerSecond <= 0 {
		return nil
	}

	for n > 0 {
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
	l.mu.Lock()
	defer l.mu.Unlock()

	l.bytesPerSecond = bytesPerSecond
	if bytesPerSecond > 0 {
		l.maxBucket = bytesPerSecond * 2
		if l.bucket > l.maxBucket {
			l.bucket = l.maxBucket
		}
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
	n, err = r.r.Read(p)
	if n > 0 && r.limiter != nil {
		if waitErr := r.limiter.WaitN(context.Background(), n); waitErr != nil {
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
	if w.limiter != nil {
		if waitErr := w.limiter.WaitN(context.Background(), len(p)); waitErr != nil {
			return 0, waitErr
		}
	}
	return w.w.Write(p)
}
