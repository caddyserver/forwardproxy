// Copyright (c) 2013 CloudFlare, Inc.

// Package bytepool is deprecated
package bytepool

import (
	"math"
	"sync"
	"time"
)

type pool struct {
	list [][]byte
	mu   sync.Mutex
}

type BytePool struct {
	list_of_pools []pool
	drainTicker   *time.Ticker
	maxSize       int
}

// Initialize BytePool structure. Starts draining regularly if
// drainPeriod is non zero. MaxSize specifies the maximum length of a
// byte slice that should be cached (rounded to the next power of 2).
//
// Deprecated: Use sync.Pool from the stdlib instead.
func (tp *BytePool) Init(drainPeriod time.Duration, maxSize uint32) {
	maxSizeLog := log2Ceil(maxSize)
	tp.maxSize = (1 << maxSizeLog) - 1
	// 32-bit catch
	if tp.maxSize <= 0 {
		tp.maxSize = math.MaxInt32
		maxSizeLog = log2Ceil(math.MaxInt32)
	}
	tp.list_of_pools = make([]pool, maxSizeLog+1)
	if drainPeriod > 0 {
		tp.drainTicker = time.NewTicker(drainPeriod)
		go func() {
			for _ = range tp.drainTicker.C {
				tp.Drain()
			}
		}()
	}
}

// Put the byte slice back in pool.
func (tp *BytePool) Put(el []byte) {
	if cap(el) < 1 || cap(el) > tp.maxSize {
		return
	}
	el = el[:cap(el)]
	o := log2Floor(uint32(cap(el)))
	p := &tp.list_of_pools[o]
	p.mu.Lock()
	p.list = append(p.list, el)
	p.mu.Unlock()
}

// Get a byte slice from the pool.
func (tp *BytePool) Get(size int) []byte {
	if size < 1 || size > tp.maxSize {
		return make([]byte, size)
	}
	var x []byte

	o := log2Ceil(uint32(size))
	p := &tp.list_of_pools[o]
	p.mu.Lock()
	if n := len(p.list); n > 0 {
		x = p.list[n-1]
		p.list[n-1] = nil
		p.list = p.list[:n-1]
	}
	p.mu.Unlock()
	if x == nil {
		x = make([]byte, 1<<o)
	}
	return x[:size]
}

// Remove all items from the pool and make them availabe for garbage
// collection.
func (tp *BytePool) Drain() {
	for o := 0; o < len(tp.list_of_pools); o++ {
		p := &tp.list_of_pools[o]
		p.mu.Lock()
		p.list = make([][]byte, 0, cap(p.list)/2)
		p.mu.Unlock()
	}
}

// Stop the drain ticker.
func (tp *BytePool) Close() {
	tp.Drain()
	if tp.drainTicker != nil {
		tp.drainTicker.Stop()
		tp.drainTicker = nil
	}
}

// Get number of entries, for debugging
func (tp *BytePool) entries() uint {
	var s uint
	for o := 0; o < len(tp.list_of_pools); o++ {
		p := &tp.list_of_pools[o]
		p.mu.Lock()
		s += uint(len(p.list))
		p.mu.Unlock()
	}
	return s
}

var multiplyDeBruijnBitPosition = [...]uint{0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30, 8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31}

// Equivalent to: uint(math.Floor(math.Log2(float64(n))))
// via: http://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
func log2Floor(v uint32) uint {
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	return multiplyDeBruijnBitPosition[uint32(v*0x07C4ACDD)>>27]
}

// Equivalent to: uint(math.Ceil(math.Log2(float64(n))))
func log2Ceil(v uint32) uint {
	var isNotPowerOfTwo uint = 1
	// Golang doesn't know how to convert bool to int - branch required
	if (v & (v - 1)) == 0 {
		isNotPowerOfTwo = 0
	}
	return log2Floor(v) + isNotPowerOfTwo
}
