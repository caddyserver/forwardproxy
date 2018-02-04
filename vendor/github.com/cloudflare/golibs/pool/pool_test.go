// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pool

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func TestPool(t *testing.T) {
	var p Pool
	if p.Get() != nil {
		t.Fatal("expected empty")
	}
	p.Put("a")
	p.Put("b")
	if g := p.Get(); g != "b" {
		t.Fatalf("got %#v; want b", g)
	}
	if g := p.Get(); g != "a" {
		t.Fatalf("got %#v; want a", g)
	}
	if g := p.Get(); g != nil {
		t.Fatalf("got %#v; want nil", g)
	}

	p.Put("c")
	p.Drain()
	if g := p.Get(); g != nil {
		t.Fatalf("got %#v; want nil after GC", g)
	}
}

func TestPoolNew(t *testing.T) {
	i := 0
	p := Pool{
		New: func() interface{} {
			i++
			return i
		},
	}
	if v := p.Get(); v != 1 {
		t.Fatalf("got %v; want 1", v)
	}
	if v := p.Get(); v != 2 {
		t.Fatalf("got %v; want 2", v)
	}
	p.Put(42)
	if v := p.Get(); v != 42 {
		t.Fatalf("got %v; want 42", v)
	}
	if v := p.Get(); v != 3 {
		t.Fatalf("got %v; want 3", v)
	}
}

// Test that Pool does not hold pointers to previously cached
// resources
func TestPoolGC(t *testing.T) {
	var p Pool
	var fin uint32
	const N = 100
	for i := 0; i < N; i++ {
		v := new(int)
		runtime.SetFinalizer(v, func(vv *int) {
			atomic.AddUint32(&fin, 1)
		})
		p.Put(v)
	}
	for i := 0; i < N; i++ {
		p.Get()
	}
	for i := 0; i < 5; i++ {
		runtime.GC()
		time.Sleep(time.Millisecond)
		// 2 pointers can remain on stack or elsewhere
		if atomic.LoadUint32(&fin) >= N-2 {
			return
		}
	}
	t.Fatalf("only %v out of %v resources are finalized",
		atomic.LoadUint32(&fin), N)
}

func TestPoolStress(t *testing.T) {
	const P = 10
	N := int(1e6)
	if testing.Short() {
		N /= 100
	}
	var p Pool
	done := make(chan bool)
	for i := 0; i < P; i++ {
		go func() {
			var v interface{} = 0
			for j := 0; j < N; j++ {
				if v == nil {
					v = 0
				}
				p.Put(v)
				v = p.Get()
				if v != nil && v.(int) != 0 {
					t.Fatalf("expect 0, got %v", v)
				}
			}
			done <- true
		}()
	}
	for i := 0; i < P; i++ {
		<-done
	}
}

func BenchmarkPool(b *testing.B) {
	procs := runtime.GOMAXPROCS(-1)
	var dec func() bool
	if unsafe.Sizeof(b.N) == 8 {
		n := int64(b.N)
		dec = func() bool {
			return atomic.AddInt64(&n, -1) >= 0
		}
	} else {
		n := int32(b.N)
		dec = func() bool {
			return atomic.AddInt32(&n, -1) >= 0
		}
	}
	var p Pool
	var wg sync.WaitGroup
	for i := 0; i < procs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dec() {
				p.Put(1)
				p.Get()
			}
		}()
	}
	wg.Wait()
}
