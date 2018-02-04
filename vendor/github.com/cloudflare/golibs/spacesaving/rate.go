// Copyright (c) 2014 CloudFlare, Inc.
//
// Tickless measurement of rates of top-k items in an infinite stream.
//
// Use exponentially decaying moving average to track rates of things per
// second for a top-K items in the stream of events. Top-K is also known as
// heavy hitters problem.
//
// Here we adapt a space saving algorithm to track rates instead of counters.
// This changes the complexity of the data strucutre - an update takes
// O(log(k)) time for k tracked items. As we use exponentially decaying moving
// average that means in a worst case we're math.Exp() function log(k) times
// on every update.
package spacesaving

import (
	"container/heap"
	"math"
	"sort"
	"time"
)

type bucket struct {
	key       string
	lastTs    int64
	rate      float64
	errLastTs int64
	errRate   float64
	idx       uint32
}

type idxEl struct {
	rate   float64
	lastTs int64
}

type ssHeap struct {
	ss *Rate
	h  []uint32
}

func (sh *ssHeap) Len() int           { return len(sh.h) }
func (ss *ssHeap) Push(x interface{}) { panic("not implemented") }
func (ss *ssHeap) Pop() interface{}   { panic("not implemented") }

func (sh *ssHeap) Less(i, j int) bool {
	ss := sh.ss
	a, b := &ss.buckets[sh.h[i]], &ss.buckets[sh.h[j]]
	rateA, rateB := a.rate, b.rate
	lastA, lastB := a.lastTs, b.lastTs

	// Formula the same as recount(), inline is faster
	if lastA >= lastB {
		// optimization. if rateB is already smaller than rateA, there
		// is no need to compute real rates. It ain't gonna grow, and
		// we can avoid running expensive math.Exp().
		if rateB >= rateA {
			rateB *= math.Exp(float64(lastA-lastB) * ss.weightHelper)
		}
	} else {
		if rateA >= rateB {
			rateA *= math.Exp(float64(lastB-lastA) * ss.weightHelper)
		}
	}

	if rateA != rateB {
		return rateA < rateB
	} else {
		// This makes difference for unitialized buckets. Rate is
		// zero, but lastTs is modified. In such case make sure to use
		// the unintialized bucket first.
		return lastA < lastB
	}
}

func (sh *ssHeap) Swap(i, j int) {
	a, b := &sh.ss.buckets[sh.h[i]], &sh.ss.buckets[sh.h[j]]
	// if a.idx != uint32(i) || b.idx != uint32(j) {
	// 	panic("desynchronized data")
	// }
	sh.h[i], sh.h[j] = sh.h[j], sh.h[i]
	a.idx, b.idx = uint32(j), uint32(i)
}

type Rate struct {
	keytobucketno map[string]uint32
	buckets       []bucket
	weightHelper  float64
	halfLife      time.Duration
	sh            ssHeap
}

// Initialize already allocated Rate structure.
//
// Size stands for number of items to track in the stream. HalfLife determines
// the time required half-charge or half-discharge a rate counter.
func (ss *Rate) Init(size uint32, halfLife time.Duration) *Rate {
	*ss = Rate{
		keytobucketno: make(map[string]uint32, size),
		buckets:       make([]bucket, size),
		weightHelper:  -math.Ln2 / float64(halfLife.Nanoseconds()),
		halfLife:      halfLife,
	}
	ss.sh.h = make([]uint32, size)
	ss.sh.ss = ss
	heap.Init(&ss.sh)
	for i := uint32(0); i < uint32(size); i++ {
		ss.sh.h[i] = i
		ss.buckets[i].idx = i
	}
	return ss
}

// Mark an event happening, using given timestamp.
//
// The implementation assumes time is monotonic, the behaviour is undefined in
// the case of time going back. This operation has logarithmic complexity.
func (ss *Rate) Touch(key string, nowTs time.Time) {
	now := nowTs.UnixNano()

	var bucket *bucket
	if bucketno, found := ss.keytobucketno[key]; found {
		bucket = &ss.buckets[bucketno]
	} else {
		bucketno = uint32(ss.sh.h[0])

		bucket = &ss.buckets[bucketno]
		delete(ss.keytobucketno, bucket.key)
		ss.keytobucketno[key] = bucketno

		bucket.key, bucket.errLastTs, bucket.errRate =
			key, bucket.lastTs, bucket.rate
	}

	if bucket.lastTs != 0 {
		bucket.rate = ss.count(bucket.rate, bucket.lastTs, now)
	}
	bucket.lastTs = now

	// Even lastTs change may change ordering.
	heap.Fix(&ss.sh, int(bucket.idx))
}

func (ss *Rate) count(rate float64, lastTs, now int64) float64 {
	deltaNs := float64(now - lastTs)
	weight := math.Exp(deltaNs * ss.weightHelper)

	if deltaNs != 0 {
		return rate*weight + (1000000000./deltaNs)*(1-weight)
	}
	return rate * weight
}

func (ss *Rate) recount(rate float64, lastTs, now int64) float64 {
	return rate * math.Exp(float64(now-lastTs)*ss.weightHelper)
}

type RateElement struct {
	Key    string
	LoRate float64
	HiRate float64
}

type sseSlice []RateElement

func (a sseSlice) Len() int           { return len(a) }
func (a sseSlice) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sseSlice) Less(i, j int) bool { return a[i].HiRate < a[j].HiRate }

// Get the lower and upper bounds of a range for all tracked elements
//
// The items are sorted by decreasing upper bound. Complexity is O(k*log(k))
// due to sorting.
func (ss *Rate) GetAll(nowTs time.Time) []RateElement {
	now := nowTs.UnixNano()
	elements := make([]RateElement, 0, len(ss.buckets))
	for _, bucket := range ss.buckets {
		if bucket.key == "" {
			continue
		}
		rate := ss.recount(bucket.rate, bucket.lastTs, now)
		errRate := ss.recount(bucket.errRate, bucket.errLastTs, now)
		elements = append(elements, RateElement{
			Key:    bucket.key,
			LoRate: rate - errRate,
			HiRate: rate,
		})
	}
	sort.Sort(sort.Reverse(sseSlice(elements)))
	return elements
}

// Get the lower and upper bounds of a range for a single element. If the
// element isn't tracked lower bound will be zero and upper bound will be the
// lowest bound of all the tracked items.
func (ss *Rate) GetSingle(key string, nowTs time.Time) (float64, float64) {
	now := nowTs.UnixNano()
	var bucket *bucket
	if bucketno, found := ss.keytobucketno[key]; found {
		bucket = &ss.buckets[bucketno]
		rate := ss.recount(bucket.rate, bucket.lastTs, now)
		errRate := ss.recount(bucket.errRate, bucket.errLastTs, now)
		return rate - errRate, rate
	} else {
		bucketno = uint32(ss.sh.h[0])
		bucket = &ss.buckets[bucketno]
		errRate := ss.recount(bucket.rate, bucket.lastTs, now)
		return 0, errRate
	}

}
