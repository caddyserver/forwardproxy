// Copyright (c) 2014 CloudFlare, Inc.

package spacesaving

import (
	"container/heap"
	"math"
	"time"
)

type srateBucket struct {
	key       string
	count     uint64
	countTs   int64
	countRate float64
	error     uint64
	errorTs   int64
	errorRate float64
	index     int
}

type srateHeap []*srateBucket

func (sh srateHeap) Len() int { return len(sh) }

func (sh srateHeap) Less(i, j int) bool {
	return sh[i].countTs < sh[j].countTs
}

func (sh srateHeap) Swap(i, j int) {
	sh[i], sh[j] = sh[j], sh[i]
	sh[i].index = i
	sh[j].index = j
}

func (sh *srateHeap) Push(x interface{}) {
	n := len(*sh)
	bucket := x.(*srateBucket)
	bucket.index = n
	*sh = append(*sh, bucket)
}

func (sh *srateHeap) Pop() interface{} {
	old := *sh
	n := len(old)
	bucket := old[n-1]
	bucket.index = -1 // for safety
	*sh = old[0 : n-1]
	return bucket
}

type SimpleRate struct {
	heap         srateHeap
	hash         map[string]*srateBucket
	weightHelper float64
	halfLife     time.Duration
	size         int
}

func (ss *SimpleRate) Init(size int, halfLife time.Duration) *SimpleRate {
	*ss = SimpleRate{
		heap:         make([]*srateBucket, 0, size),
		hash:         make(map[string]*srateBucket, size),
		weightHelper: -math.Ln2 / float64(halfLife.Nanoseconds()),
		halfLife:     halfLife,
		size:         size,
	}
	return ss
}

func (ss *SimpleRate) count(rate float64, lastTs, now int64) float64 {
	deltaNs := float64(now - lastTs)
	weight := math.Exp(deltaNs * ss.weightHelper)

	if deltaNs > 0 && lastTs != 0 {
		return rate*weight + (1000000000./deltaNs)*(1-weight)
	}
	return rate * weight
}

func (ss *SimpleRate) recount(rate float64, lastTs, now int64) float64 {
	return rate * math.Exp(float64(now-lastTs)*ss.weightHelper)
}

func (ss *SimpleRate) Touch(key string, nowTs time.Time) {
	var (
		found    bool
		bucket   *srateBucket
		now      = nowTs.UnixNano()
	)
	bucket, found = ss.hash[key];
	if found {
		// we already have the correct bucket
	} else if len(ss.heap) < ss.size {
		// create new bucket
		bucket = &srateBucket{}
		ss.hash[key] = bucket
		bucket.key = key
		heap.Push(&ss.heap, bucket)
	} else {
		// use minimum bucket
		bucket = ss.heap[0]
		delete(ss.hash, bucket.key)
		ss.hash[key] = bucket
		bucket.error, bucket.errorTs, bucket.errorRate =
			bucket.count, bucket.countTs, bucket.countRate
		bucket.key = key
	}

	bucket.count += 1
	bucket.countRate = ss.count(bucket.countRate, bucket.countTs, now)
	bucket.countTs = now

	heap.Fix(&ss.heap, bucket.index)
}

type srateElement struct {
	Key     string
	LoCount uint64
	HiCount uint64
	LoRate  float64
	HiRate  float64
}

func (ss *SimpleRate) GetAll(nowTs time.Time) []srateElement {
	now := nowTs.UnixNano()

	elements := make([]srateElement, 0, len(ss.heap))
	for _, b := range ss.heap {
		rate := ss.recount(b.countRate, b.countTs, now)
		errRate := ss.recount(b.errorRate, b.errorTs, now)
		elements = append(elements, srateElement{
			Key:     b.key,
			LoCount: b.count - b.error,
			HiCount: b.count,
			LoRate:  rate - errRate,
			HiRate:  rate,
		})
	}
	return elements
}
