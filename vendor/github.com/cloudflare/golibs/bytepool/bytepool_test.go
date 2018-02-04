package bytepool

import (
	"math"
	"testing"
	"time"
)

var mathTestData = []struct {
	n    uint32
	f, c uint
}{
	{0, 0, 0},
	{1, 0, 0},
	{2, 1, 1},
	{3, 1, 2},
	{4, 2, 2},
	{5, 2, 3},
	{6, 2, 3},
	{7, 2, 3},
	{8, 3, 3},
	{15, 3, 4},
	{16, 4, 4},
	{17, 4, 5},
	{math.MaxUint32 - 1, 31, 32},
	{math.MaxUint32, 31, 32},
}

func TestMath(t *testing.T) {
	t.Parallel()

	for _, l := range mathTestData {
		if log2Floor(l.n) != l.f || log2Ceil(l.n) != l.c {
			t.Errorf("x=log2(%d) Expecting ⌊x⌋=%d ⌈x⌉=%d got ⌊x⌋=%d ⌈x⌉=%d",
				l.n, l.f, l.c, log2Floor(l.n), log2Ceil(l.n))
		}
	}
}

func TestPool(t *testing.T) {
	t.Parallel()

	var p BytePool
	p.Init(0, 128)

	v := p.Get(31)
	if cap(v) != 32 || len(v) != 31 {
		t.Fatal("wrong capacity or length")
	}
	p.Put(v[:1])

	v = p.Get(30)
	if cap(v) != 32 || len(v) != 30 {
		t.Fatal("wrong capacity or length")
	}

	e := make([]byte, 0, 127)
	p.Put(e)
	v = p.Get(64)

	if cap(v) != 127 || len(v) != 64 {
		t.Fatalf("wrong capacity or length %d %d", cap(v), len(v))
	}

	v = p.Get(127)
	if cap(v) != 128 || len(v) != 127 {
		t.Fatalf("wrong capacity or length %d %d", cap(v), len(v))
	}

	v = p.Get(128)
	if cap(v) != 128 || len(v) != 128 {
		t.Fatalf("wrong capacity or length %d %d", cap(v), len(v))
	}
}

func TestDrain(t *testing.T) {
	t.Parallel()

	var p BytePool
	p.Init(1*time.Millisecond, 128)
	p.Put(make([]byte, 127))
	time.Sleep(100 * time.Millisecond)

	if p.entries() != 0 {
		t.Fatal("expected the pool to be drained")
	}
	p.Close()
}

func TestLimits(t *testing.T) {
	t.Parallel()

	var ti	int
	var p 	BytePool
	p.Init(0, 127)

	p.Put(make([]byte, 129))
	if p.entries() != 0 {
		t.Fatal("expected the pool to be empty")
	}

	p.Put(make([]byte, 127))
	if p.entries() != 1 {
		t.Fatal("expected the pool to have a single item")
	}

	p.Put(make([]byte, 0))
	if p.entries() != 1 {
		t.Fatal("expected different pool length")
	}

	p.Put(make([]byte, 1))
	if p.entries() != 2 {
		t.Fatal("expected different pool length")
	}

	p.Close()

	p.Init(0, math.MaxUint32)
	p.Put(make([]byte, 129))
	if p.entries() != 1 {
		t.Fatal("expected different pool length")
	}

	p.Put(make([]byte, math.MaxUint32 + 1))
	if p.entries() != 1 {
		t.Fatal("expected the pool to have a single item")
	}

	p.Put(make([]byte, math.MaxInt32 + 1))
	ti = (1 << log2Ceil(math.MaxUint32)) - 1
	if ti <= 0 {
		// 32-bit systems: Put() slice-size math.MaxInt32 + 1 fails
		if p.entries() != 1 {
			t.Fatal("expected the pool to have a single item")
		}
	} else {
		if p.entries() != 2 {
			t.Fatal("expected the pool to have two items")
		}
	}

	p.Drain()
	p.Put(nil)
	if p.entries() != 0 {
		t.Fatal("expected different pool length")
	}
}
