// Copyright (c) 2013 CloudFlare, Inc.

// Circular buffer data structure.
//
// This implementation avoids memory allocations during push/pop
// operations. It supports nonblocking push (ie: old data gets
// evicted). You can pop an item from the top. You can access this
// data structure concurrently, using an internal guarding mutex lock.
//
// An item can get evicted when NBPush is called. During the call the
// buffer will try to call the Evict callback. If the callback is
// present the NBPush fun runs it and returns nil. Otherwise NBPush
// returns the evicted value or nil if there still is free space in
// the stack.
//
// This package exports three things:
//     StackPusher interface
//     StackGetter interface
//     CircularBuffer structure
package circularbuffer

import (
	"sync"
)

// An interface used to add things to the stack.
type StackPusher interface {
	// Non-blocking push. Will evict items from the cache if there
	// isn't enough space available.
	NBPush(interface{}) interface{}

	// Non-blocking push. Wil put item in the buffer only if there
	// is free space.
	NBOptionalPush(interface{}) interface{}
}

// An interface used to get items from the stack.
type StackGetter interface {
	// Get an item from the beginning of the stack (oldest),
	// blocking.
	Get() interface{}
	// Blocking pop an item from the end of the stack (newest),
	// blocking.
	Pop() interface{}
}

type CircularBuffer struct {
	start  uint // idx of first used cell
	pos    uint // idx of first unused cell
	buffer []interface{}
	size   uint
	avail  chan bool // poor man's semaphore. len(avail) is always equal to (size + pos - start) % size
	lock   sync.Mutex
	// Callback used by NBPush if an item needs to be evicted from
	// the stack.
	Evict func(v interface{})
}

// Create CircularBuffer object with a prealocated buffer of a given size.
func NewCircularBuffer(size uint) *CircularBuffer {
	return &CircularBuffer{
		buffer: make([]interface{}, size),
		size:   size,
		avail:  make(chan bool, size),
	}
}

// Nonblocking push. If the Evict callback is not set returns the
// evicted item (if any), otherwise nil.
func (b *CircularBuffer) NBPush(v interface{}) interface{} {
	var evictv interface{}
	b.lock.Lock()

	if b.buffer[b.pos] != nil {
		panic("not nil")
	}

	b.buffer[b.pos] = v
	b.pos = (b.pos + 1) % b.size
	if b.pos == b.start {
		// Remove old item from the bottom of the stack to
		// free the space for the new one. This doesn't change
		// the length of the stack, so no need to touch avail.
		evictv = b.buffer[b.start]
		b.buffer[b.start] = nil
		b.start = (b.start + 1) % b.size
	} else {
		select {
		case b.avail <- true:
		default:
			panic("Sending to avail channel must never block")
		}
	}
	b.lock.Unlock()
	if evictv != nil && b.Evict != nil {
		// Outside the lock. User callback may in want to add
		// an item to the stack.
		b.Evict(evictv)
		return nil
	}
	return evictv
}

// Nonblocking push. Push only if there is space. Otherwise evict v.
func (b *CircularBuffer) NBOptionalPush(v interface{}) interface{} {
	var evictv interface{}
	b.lock.Lock()

	if b.buffer[b.pos] != nil {
		panic("not nil")
	}

	if (b.start+b.size-1)%b.size == b.pos {
		// evict v, don't change anything
		evictv = v
	} else {
		// Plenty of space, just add as usual
		b.buffer[b.pos] = v
		b.pos = (b.pos + 1) % b.size
		select {
		case b.avail <- true:
		default:
			panic("Sending to avail channel must never block")
		}
	}
	b.lock.Unlock()
	if evictv != nil && b.Evict != nil {
		// Outside the lock. User callback may in want to add
		// an item to the stack.
		b.Evict(evictv)
		return nil
	}
	return evictv
}

// Get an item from the beginning of the queue (oldest), blocking.
func (b *CircularBuffer) Get() interface{} {
	_ = <-b.avail

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.start == b.pos {
		panic("Trying to get from empty buffer")
	}

	v := b.buffer[b.start]
	b.buffer[b.start] = nil
	b.start = (b.start + 1) % b.size

	return v
}

// Blocking pop an item from the end of the queue (newest), blocking.
func (b *CircularBuffer) Pop() interface{} {
	_ = <-b.avail

	b.lock.Lock()
	defer b.lock.Unlock()

	if b.start == b.pos {
		panic("Can't pop from empty buffer")
	}

	b.pos = (b.size + b.pos - 1) % b.size
	v := b.buffer[b.pos]
	b.buffer[b.pos] = nil

	return v
}

// Is the buffer empty?
func (b *CircularBuffer) Empty() bool {
	// b.avail is a channel, no need for a lock
	return len(b.avail) == 0
}

// Length of the buffer
func (b *CircularBuffer) Length() int {
	// b.avail is a channel, no need for a lock
	return len(b.avail)
}
