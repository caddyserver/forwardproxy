// Copyright (c) 2014 CloudFlare, Inc.

package spacesaving

type countBucket struct {
	key   string
	count uint64
	error uint64
}

type Count struct {
	olist []countBucket
	hash  map[string]uint32
}

func (ss *Count) Init(size int) *Count {
	*ss = Count{
		olist: make([]countBucket, size),
		hash:  make(map[string]uint32, size),
	}
	return ss
}

func (ss *Count) Touch(key string) {
	var (
		bucketno uint32
		found    bool
		bucket   *countBucket
	)

	if bucketno, found = ss.hash[key]; found {
		bucket = &ss.olist[bucketno]
	} else {
		bucketno = 0
		bucket = &ss.olist[bucketno]
		delete(ss.hash, bucket.key)
		ss.hash[key] = bucketno
		bucket.error = bucket.count
		bucket.key = key
	}

	bucket.count += 1

	for {
		if bucketno == uint32(len(ss.olist))-1 {
			break
		}

		b1 := &ss.olist[bucketno]
		b2 := &ss.olist[bucketno+1]
		if b1.count < b2.count {
			break
		}

		ss.hash[b1.key] = bucketno + 1
		ss.hash[b2.key] = bucketno
		*b1, *b2 = *b2, *b1
		bucketno += 1
	}
}

type Element struct {
	Key     string
	LoCount uint64
	HiCount uint64
}

func (ss *Count) GetAll() []Element {
	elements := make([]Element, 0, len(ss.hash))
	for i := len(ss.olist) - 1; i >= 0; i -= 1 {
		b := &ss.olist[i]
		if b.key == "" {
			continue
		}
		elements = append(elements, Element{
			Key:     b.key,
			LoCount: b.count - b.error,
			HiCount: b.count,
		})
	}
	return elements
}

func (ss *Count) Reset() {
	empty := countBucket{}
	for i, _ := range ss.olist {
		delete(ss.hash, ss.olist[i].key)
		ss.olist[i] = empty
	}
}
