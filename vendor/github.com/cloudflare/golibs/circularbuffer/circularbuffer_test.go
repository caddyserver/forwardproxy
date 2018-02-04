// Copyright (c) 2013 CloudFlare, Inc.

package circularbuffer

import (
	"testing"
)

func (b *CircularBuffer) verifyIsEmpty() bool {
	b.lock.Lock()
	defer b.lock.Unlock()

	e := len(b.avail) == 0
	if e {
		if b.pos != b.start {
			panic("desychronized state")
		}
	}
	return e
}

func TestSyncGet(t *testing.T) {
	c := NewCircularBuffer(10)

	for i := 0; i < 4; i++ {
		c.NBPush(i)
	}

	for i := 0; i < 4; i++ {
		v := c.Get().(int)
		if i != v {
			t.Error(v)
		}
	}

	if c.verifyIsEmpty() != true {
		t.Error("not empty")
	}
}

func TestSyncOverflow(t *testing.T) {
	c := NewCircularBuffer(10) // up to 9 items in the buffer

	for i := 0; i < 9; i++ {
		v := c.NBPush(i)
		if v != nil {
			t.Error(v)
		}
	}
	v := c.NBPush(9)
	if v != 0 {
		t.Error(v)
	}

	for i := 1; i < 10; i++ {
		v := c.Get().(int)
		if i != v {
			t.Error(v)
		}
	}

	if c.verifyIsEmpty() != true {
		t.Error("not empty")
	}
}

func TestAsyncGet(t *testing.T) {
	c := NewCircularBuffer(10)

	go func() {
		for i := 0; i < 4; i++ {
			v := c.Get().(int)
			if i != v {
				t.Error(i)
			}
		}

		if c.verifyIsEmpty() != true {
			t.Error("not empty")
		}
	}()

	c.NBPush(0)
	c.NBPush(1)
	c.NBPush(2)
	c.NBPush(3)
}

func TestSyncPop(t *testing.T) {
	c := NewCircularBuffer(10)

	c.NBPush(3)
	c.NBPush(2)
	c.NBPush(1)
	c.NBPush(0)

	for i := 0; i < 4; i++ {
		v := c.Pop().(int)
		if i != v {
			t.Error(v)
		}
	}

	if c.verifyIsEmpty() != true {
		t.Error("not empty")
	}
}

func TestASyncPop(t *testing.T) {
	c := NewCircularBuffer(10)

	go func() {
		for i := 0; i < 4; i++ {
			v := c.Pop().(int)
			if i != v {
				t.Error(v)
			}
		}

		if c.verifyIsEmpty() != true {
			t.Error("not empty")
		}
	}()

	c.NBPush(3)
	c.NBPush(2)
	c.NBPush(1)
	c.NBPush(0)
}

func TestSyncOverflowEvictCallback(t *testing.T) {
	c := NewCircularBuffer(10) // up to 9 items in the buffer

	evicted := 0
	c.Evict = func(v interface{}) {
		if v.(int) != evicted {
			t.Error(v)
		}
		evicted += 1
	}

	for i := 0; i < 18; i++ {
		v := c.NBPush(i)
		if v != nil {
			t.Error(v)
		}
	}

	for i := 9; i < 18; i++ {
		v := c.Get().(int)
		if i != v {
			t.Error(v)
		}
	}

	if evicted != 9 {
		t.Error(evicted)
	}

	if c.verifyIsEmpty() != true {
		t.Error("not empty")
	}
}

func drain(c *CircularBuffer) []int {
	n := make([]int, 0)
	for c.Empty() != true {
		n = append(n, c.Get().(int))
	}
	return n
}

func cmp(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		switch {
		case a[i] > b[i]:
			return 1
		case a[i] < b[i]:
			return -1
		}
	}
	switch {
	case len(a) > len(b):
		return 1
	case len(a) < len(b):
		return -1
	}
	return 0
}

func TestEject(t *testing.T) {
	c := NewCircularBuffer(5)

	c.NBPush(0)
	c.NBPush(1)
	c.NBPush(2)
	c.NBPush(3)
	x := drain(c)
	if cmp(x, []int{0, 1, 2, 3}) != 0 {
		t.Error("x %v", x)
	}

	c.NBPush(0)
	c.NBPush(1)
	c.NBPush(2)
	c.NBPush(3)
	c.NBPush(4)
	x = drain(c)
	if cmp(x, []int{1, 2, 3, 4}) != 0 {
		t.Error("x %v", x)
	}
}

func TestOptionalPush(t *testing.T) {
	c := NewCircularBuffer(5)

	c.NBPush(0)
	c.NBPush(1)
	c.NBPush(2)
	c.NBPush(3)
	x := drain(c)
	if cmp(x, []int{0, 1, 2, 3}) != 0 {
		t.Error("x %v", x)
	}

	// No evict
	c.NBPush(0)
	c.NBPush(1)
	c.NBPush(2)
	c.NBOptionalPush(3)
	x = drain(c)
	if cmp(x, []int{0, 1, 2, 3}) != 0 {
		t.Error("x %v", x)
	}

	// Evict us
	c.NBPush(0)
	c.NBPush(1)
	c.NBPush(2)
	c.NBPush(3)
	c.NBOptionalPush(4)
	x = drain(c)
	if cmp(x, []int{0, 1, 2, 3}) != 0 {
		t.Error("x %v", x)
	}

	// Evict us, with callback
	c.Evict = func(v interface{}) {
		if v.(int) != 4 {
			t.Error(v)
		}
	}
	c.NBPush(0)
	c.NBPush(1)
	c.NBPush(2)
	c.NBPush(3)
	c.NBOptionalPush(4)
	x = drain(c)
	if cmp(x, []int{0, 1, 2, 3}) != 0 {
		t.Error("x %v", x)
	}
}
