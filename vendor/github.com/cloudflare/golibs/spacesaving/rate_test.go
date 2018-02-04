// Copyright (c) 2014 CloudFlare, Inc.

package spacesaving

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

var listOfTestVectors = [][]struct {
	update bool
	key    string
	delay  float64
	rateLo float64
	rateHi float64
}{
	// Two slots, half life of 1 second
	// Sanity check, feeding one packet per second
	{
		{false, "a", 1, 0, 0},
		{true, "a", 1, 0, 0},
		{true, "a", 1, 0.5, 0.5},
		{true, "a", 1, 0.75, 0.75},
		{true, "a", 1, 0.875, 0.875},
		{true, "a", 1, 0.9375, 0.9375},
		{true, "a", 1, 0.96875, 0.96875},
		{true, "a", 1, 0.984375, 0.984375},
		{true, "a", 1, 0.9921875, 0.9921875},
		{true, "a", 1, 0.99609375, 0.99609375},
		{true, "a", 1, 0.998046875, 0.998046875},

		// Discharging over 5 seconds
		{false, "a", 1, 0.4990234375, 0.4990234375},
		{false, "a", 1, 0.24951171875, 0.24951171875},
		{false, "a", 1, 0.12475585937500003, 0.12475585937500003},
		{false, "a", 1, 0.0623779296875, 0.0623779296875},
		{false, "a", 1, 0.03118896484375, 0.03118896484375},

		// A small number remains after 30 seconds of discharge
		{false, "a", 25, 0.000000000929503585211933486330,
			0.000000000929503585211933486330},
	},

	// Sanity check of yielding
	{
		{false, "a", 1, 0, 0},
		{false, "b", 0, 0, 0},

		{true, "a", 1, 0, 0},
		{true, "b", 0, 0, 0},

		{true, "a", 1, 0.5, 0.5},
		{true, "b", 0, 0.5, 0.5},

		{true, "c", 1, 0.5, 0.75},
		{false, "a", 0, 0.25, 0.25},
		{false, "b", 0, 0, 0.25}, // b is yielded

		{true, "a", 0, 0.75, 0.75},
		{false, "b", 0, 0, 0.75}, // b is yielded
		{false, "c", 0, 0.5, 0.75},

		{true, "b", 0, 0, 0.75},

		{false, "a", 0, 0.0, 0.75}, // a is yielded
		{false, "b", 0, 0.0, 0.75},
		{false, "c", 0, 0.5, 0.75},
	},
}

func TestRate(t *testing.T) {
	t.Parallel()

	for testNo, testVector := range listOfTestVectors {
		ts := time.Now()
		ss := (&Rate{}).Init(2, 1*time.Second)
		for i, l := range testVector {
			ts = ts.Add(time.Duration(l.delay *
				float64(time.Second.Nanoseconds())))

			if l.update {
				ss.Touch(l.key, ts)
			}

			if l.rateLo != -1 || l.rateHi != -1 {
				rateLo, rateHi := ss.GetSingle(l.key, ts)
				if l.rateLo != -1 && rateLo != l.rateLo {
					t.Errorf("test %v line %v: rateLo "+
						"expected=%v got=%v",
						testNo, i, l.rateLo, rateLo)
				}
				if l.rateHi != -1 && rateHi != l.rateHi {
					t.Errorf("test %v line %v: rateHi "+
						"expected=%v got=%v",
						testNo, i, l.rateHi, rateHi)
				}
			}
		}
	}
}

func TestRateGetAll(t *testing.T) {
	t.Parallel()

	ss := (&Rate{}).Init(2, 1*time.Second)

	ss.Touch("a",time.Now())
	ss.Touch("a",time.Now())
	ss.Touch("b",time.Now())
	ss.Touch("b",time.Now())
	ss.Touch("c",time.Now())
	ss.Touch("c",time.Now())

	el := ss.GetAll(time.Now())
	if el[0].Key != "c" {
		t.Errorf("%v\n", el[0])
	}
	if el[1].Key != "b" {
		t.Errorf("%v\n", el[1])
	}
	if len(el) != 2 {
		t.Error("expecting lenght = 2")
	}

	ss.Touch("b",time.Now())
	ss.Touch("b",time.Now())
	ss.Touch("b",time.Now())
	ss.Touch("b",time.Now())

	el = ss.GetAll(time.Now())
	if el[0].Key != "b" {
		t.Errorf("%v\n", el[0])
	}
	if el[1].Key != "c" {
		t.Errorf("%v\n", el[1])
	}
}

func TestRateGetAllCover(t *testing.T) {
	t.Parallel()

	ss := (&Rate{}).Init(2, 1*time.Second)
	el := ss.GetAll(time.Now())

	if len(el) != 0 {
		t.Error("expecting lenght = 0")
	}


}


// Benchmark updating times with 10% hit rate.
func BenchmarkTouch16384_ten(bb *testing.B) {
	benchmark(bb, 16384, 0.1)
}

func BenchmarkTouch32768_ten(bb *testing.B) {
	benchmark(bb, 32768, 0.1)
}

// Benchmark updating times with 50% hit rate.
func BenchmarkTouch16384_fifty(bb *testing.B) {
	benchmark(bb, 16384, 0.5)
}

func BenchmarkTouch32768_fifty(bb *testing.B) {
	benchmark(bb, 32768, 0.5)
}

// Benchmark updating times with 90% hit rate.
func BenchmarkTouch16384_ninety(bb *testing.B) {
	benchmark(bb, 16384, 0.9)
}

func BenchmarkTouch32768_ninety(bb *testing.B) {
	benchmark(bb, 32768, 0.9)
}

// Benchmark updating items with 100% hit rate.
func BenchmarkTouch1024_hundred(bb *testing.B) {
	benchmark(bb, 1024, 1)
}

func BenchmarkTouch2048_hundred(bb *testing.B) {
	benchmark(bb, 2048, 1)
}

func BenchmarkTouch4096_hundred(bb *testing.B) {
	benchmark(bb, 4096, 1)
}

func BenchmarkTouch8192_hundred(bb *testing.B) {
	benchmark(bb, 8192, 1)
}

func BenchmarkTouch16384_hundred(bb *testing.B) {
	benchmark(bb, 16384, 1)
}

func BenchmarkTouch32768_hundred(bb *testing.B) {
	benchmark(bb, 32768, 1)
}

func benchmark(bb *testing.B, n int, hitrate float64) {
	ss := (&Rate{}).Init(uint32(n), 1*time.Second)

	for i := 0; i < n; i += 1 {
		ss.Touch(string(i), time.Now())
	}

	// warmup
	for i := 0; i < n; i += 1 {
		ss.Touch(string(rand.Intn(n)), time.Now())
	}

	topRange := int(float64(n) * 1 / hitrate)
	bb.ResetTimer()
	for i := 0; i < bb.N; i += 1 {
		ss.Touch(string(rand.Intn(topRange)), time.Now())
	}
}

// math.Exp is the slowest operation in this implementation. Measure just how
// slow it is. Usually calling math.Exp() is responsible for ~30% of the CPU.
func BenchmarkMathExp(bb *testing.B) {
	x := rand.Float64()
	for i := 0; i < bb.N; i += 1 {
		math.Exp(x)
	}
}
