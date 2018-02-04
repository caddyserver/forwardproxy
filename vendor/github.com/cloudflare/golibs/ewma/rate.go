// Copyright (c) 2014 CloudFlare, Inc.
//
// Facilities for tickless measurment of rates
//
// Apply exponentially decaying moving average to count rates of
// things per second. Useful for various metrics.
package ewma

import (
	"time"
)

type EwmaRate struct {
	Ewma
}

// Nanoseconds in second
const nanosec = float64(1000000000)

// Allocate a new NewEwmaRate structure
//
// halfLife it the time takes for a half charge or half discharge
func NewEwmaRate(halfLife time.Duration) *EwmaRate {
	return (&EwmaRate{}).Init(halfLife)
}

// Initialize already allocated NewEwmaRate structure
//
// halfLife it the time takes for a half charge or half discharge
func (r *EwmaRate) Init(halfLife time.Duration) *EwmaRate {
	r.Ewma.Init(halfLife)
	return r
}

// Notify of an event happening.
//
// Uses system clock to determine current time. Returns current rate.
func (r *EwmaRate) UpdateNow() float64 {
	return r.Update(time.Now())
}

// Notify of an event happening, with specified current time.
//
// Returns current rate.
func (r *EwmaRate) Update(now time.Time) float64 {
	timeDelta := now.Sub(r.lastTimestamp)
	return r.Ewma.Update(nanosec/float64(timeDelta.Nanoseconds()), now)
}

// Read the rate of events per second.
//
// Uses system clock to determine current time.
func (r *EwmaRate) CurrentNow() float64 {
	return r.Current(time.Now())
}

// Read the rate of events per second, with specified current time.
func (r *EwmaRate) Current(now time.Time) float64 {
	if r.lastTimestamp.IsZero() || r.lastTimestamp == now || now.Before(r.lastTimestamp) {
		return r.Ewma.Current
	}

	timeDelta := now.Sub(r.lastTimestamp)

	// Count as if nothing was received since last update and
	// don't save anything.
	return r.count(0, timeDelta)
}
