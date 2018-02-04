// package tokenbucket implements a simple token bucket filter.
package tokenbucket

import (
	"math/rand"
	"time"
)

type item struct {
	credit uint64
	prev   uint64
}

// Filter implements a token bucket filter.
type Filter struct {
	creditMax uint64
	touchCost uint64

	key0 uint64
	key1 uint64

	items []item
}

// New creates a new token bucket filter with num buckets, accruing tokens at rate per second. The depth specifies
// the depth of the bucket.
func New(num int, rate float64, depth uint64) *Filter {
	b := new(Filter)
	if depth <= 0 {
		panic("depth of bucket must be greater than 0")
	}
	b.touchCost = uint64((float64(1*time.Second) / rate))
	b.creditMax = depth * b.touchCost
	b.items = make([]item, num)

	// Not the full range of a uint64, but we can
	// live with 2 bits of entropy missing
	b.key0 = uint64(rand.Int63())
	b.key1 = uint64(rand.Int63())

	return b
}

func (b *Filter) touch(it *item) bool {
	now := uint64(time.Now().UnixNano())
	delta := now - it.prev
	it.credit += delta
	it.prev = now

	if it.credit > b.creditMax {
		it.credit = b.creditMax
	}

	if it.credit > b.touchCost {
		it.credit -= b.touchCost
		return true
	}
	return false
}

// Touch finds the token bucket for d, takes a token out of it and reports if
// there are still tokens left in the bucket.
func (b *Filter) Touch(d []byte) bool {
	n := len(b.items)
	h := hash(b.key0, b.key1, d)
	i := h % uint64(n)
	return b.touch(&b.items[i])
}
