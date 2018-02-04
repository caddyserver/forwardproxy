// Copyright (c) 2014 CloudFlare, Inc.

package ewma

import (
	"testing"
	"time"
)

type testTupleEwma struct {
	v     float64
	delay float64
	cur   float64
}

var testVectorEwma = [][]testTupleEwma{
	// Sanity check (half life is 60 seconds)
	{
		{10, 60, 5}, // half charge time is 1 minute
		{10, 60, 7.5},
		{10, 60, 8.75},
		{10, 180, 9.84375}, // full charge is quite high
		{10, 3400, 10},     // depending on floats precision
		{0, 60, 5},         // half discharge time is minute
		{0, 60, 2.5},
		{0, 60, 1.25},
		{0, 60, 0.625},
		{0, 60, 0.3125},
	},

	// Charging 4 times every second is the same as...
	{
		{10, 1, 0.1148597964710385},
		{10, 1, 0.22840031565754015},
		{10, 1, 0.34063671075154406},
		{10, 1, 0.4515839608958339},
	},
	// ...charging once after four seconds.
	{
		{10, 4, 0.45158396089583497},
	},

	// And for fun charging exponencially
	{
		{1, 60, 0.5},
		{2, 60, 1.25},
		{4, 60, 2.625},
		{8, 60, 5.3125},
		{16, 60, 10.65625},
		{32, 60, 21.328125},
		{64, 60, 42.6640625},
	},
	// ...charging once after four seconds.
	{
		{10, 4, 0.45158396089583497},
	},
}

func TestEwma(t *testing.T) {
	for testNo, test := range testVectorEwma {
		e := NewEwma(time.Duration(1 * time.Minute))

		// Feed the 0th timestamp
		ts := time.Now()
		e.Update(0, ts)

		if e.Current != 0 {
			t.Errorf("Rate after init should be zero")
		}

		for lineNo, l := range test {
			ts = ts.Add(time.Duration(l.delay * float64(time.Second.Nanoseconds())))
			e.Update(l.v, ts)
			if e.Current != l.cur {
				t.Errorf("Test %d, line %d: %v != %v",
					testNo, lineNo, e.Current, l.cur)
			}
		}
	}
}

func TestEwmaCoverErrors(t *testing.T) {
	e := NewEwma(time.Duration(1 * time.Minute))

	ts := time.Now()
	e.Update(0, ts)

	e.Update(0, ts.Add(-1*time.Second))
	if e.Current != 0 {
		t.Error("expecting 0")
	}

	e.UpdateNow(0)
	if e.Current != 0 {
		t.Error("expecting 0")
	}
}
