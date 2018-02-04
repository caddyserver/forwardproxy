// Copyright (c) 2014 CloudFlare, Inc.
//
// Tickless implementation of exponentially decaying moving average
//
// Most of EWMA implementations update values every X seconds. This is
// suboptimal. Instead of having a ticker goroutine it is possible to
// adjust the weight accordingly and have a moving average updated on
// the fly.
//
// Everyone is familiar with EWMA - it's wide used as the load average
// smoothing algorithm.
package ewma

import (
	"math"
	"time"
)

type Ewma struct {
	lastTimestamp time.Time
	weightHelper  float64

	// Current value of the moving average
	Current float64
}

// Allocate a new NewEwma structure
//
// halfLife it the time takes for a half charge or half discharge
func NewEwma(halfLife time.Duration) *Ewma {
	return (&Ewma{}).Init(halfLife)
}

// Initialize already allocated NewEwma structure
//
// halfLife it the time takes for a half charge or half discharge
func (e *Ewma) Init(halfLife time.Duration) *Ewma {
	*e = Ewma{
		weightHelper: -math.Ln2 / float64(halfLife.Nanoseconds()),
	}
	return e
}

func (e *Ewma) count(next float64, timeDelta time.Duration) float64 {
	// weight = math.Exp(timedelta * math.Log(0.5) / halfLife)
	weight := math.Exp(float64(timeDelta.Nanoseconds()) * e.weightHelper)
	return e.Current*weight + next*(1-weight)
}

// Update moving average with the value.
//
// Uses system clock to determine current time to count wight. Returns
// updated moving avarage.
func (e *Ewma) UpdateNow(value float64) float64 {
	return e.Update(value, time.Now())
}

// Update moving average with the value, using given time as weight
//
// Returns updated moving avarage.
func (e *Ewma) Update(next float64, timestamp time.Time) float64 {
	if timestamp.Before(e.lastTimestamp) || timestamp == e.lastTimestamp {
		return e.Current
	}

	if e.lastTimestamp.IsZero() {
		// Ignore the first sample
		e.lastTimestamp = timestamp
		return e.Current
	}

	timeDelta := timestamp.Sub(e.lastTimestamp)
	e.lastTimestamp = timestamp

	e.Current = e.count(next, timeDelta)
	return e.Current
}
