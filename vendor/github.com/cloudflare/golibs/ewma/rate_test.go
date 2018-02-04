// Copyright (c) 2014 CloudFlare, Inc.

package ewma

import (
	"testing"
	"time"
)

type testTupleRate struct {
	packet bool
	delay  float64
	cur    float64
}

var testVectorRate = [][]testTupleRate{
	// Sanity check (half life is 1 second)
	{
		// Feeding packets every second gets to 1 pps eventually
		{false, 1, 0},
		{true, 1, 0},
		{true, 1, 0.5},
		{true, 1, 0.75},
		{true, 1, 0.875},
		{true, 1, 0.9375},
		{true, 1, 0.96875},
		{true, 1, 0.984375},
		{true, 1, 0.9921875},
		{true, 1, 0.99609375},
		{true, 1, 0.998046875},

		// Stop over 5 seconds
		{false, 1, 0.4990234375},
		{false, 1, 0.24951171875},
		{false, 1, 0.12475585937500003},
		{false, 1, 0.0623779296875},
		{false, 1, 0.03118896484375},

		// A small number after 30 seconds discharge
		{false, 25, 0.000000000929503585211933486330},
	},

	// Burst of 10, 1ms apart, gets us to ~7 pps
	{
		{true, 1, 0},
		{true, 0.001, -1}, {true, 0.001, -1}, {true, 0.001, -1}, {true, 0.001, -1}, {true, 0.001, -1},
		{true, 0.001, -1}, {true, 0.001, -1}, {true, 0.001, -1}, {true, 0.001, -1}, {true, 0.001, -1},
		{false, 0, 6.9075045629642595},
		{false, 1, 3.453752281482129760092902870383},
		{false, 1, 1.726876140741064880046451435192},
	},

	// 10 packets 100ms apart, get 5 pps
	{
		{true, 1, 0},
		{true, 0.1, -1}, {true, 0.1, -1}, {true, 0.1, -1}, {true, 0.1, -1}, {true, 0.1, -1},
		{true, 0.1, -1}, {true, 0.1, -1}, {true, 0.1, -1}, {true, 0.1, -1}, {true, 0.1, -1},
		{false, 0, 5.000000000000002},
		{false, 1, 2.500000000000000888178419700125},
		{false, 1, 1.250000000000000444089209850063},
	},
}

func TestRate(t *testing.T) {
	for testNo, test := range testVectorRate {
		ts := time.Now()
		e := NewEwmaRate(time.Duration(1 * time.Second))

		for lineNo, l := range test {
			ts = ts.Add(time.Duration(l.delay * float64(time.Second.Nanoseconds())))
			if l.packet {
				e.Update(ts)
			}
			if l.cur != -1 && e.Current(ts) != l.cur {
				t.Errorf("Test %d, line %d: %.30f != %.30f",
					testNo, lineNo, e.Current(ts), l.cur)
			}
		}
	}
}

func TestRateCoverErrors(t *testing.T) {
	e := NewEwmaRate(time.Duration(1 * time.Second))

	if e.CurrentNow() != 0 {
		t.Error("expecting 0")
	}

	e.UpdateNow()
	rate := e.CurrentNow()
	if !(rate >= 0.0 && rate < 0.2) {
		// depending on the speed of the CPU
		t.Errorf("expecting 0 got %v", rate)
	}
}
