package tokenbucket_test

import (
	"github.com/cloudflare/golibs/tokenbucket"
	"testing"
	"time"
)

func TestInvalidBurst(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic, got nothing")
		}
	}()
	_ = tokenbucket.New(1, 300, 0)
}

func TestBucketDepth(t *testing.T) {
	b := tokenbucket.New(1, 300, 300)
	n := 0
	// With a bucket the size of the rate
	// we should expect the rate * 1s to make it through the filter
	// Because we can't touch simultaneously, use a fudge factor.
	for b.Touch(nil) {
		n++
	}
	if n != 300 {
		t.Fatal("expected 300 touches to be sucessful; got ", n)
	}
	now := time.Now()
	for !b.Touch(nil) {
	}
	// Filter allowed us through. This should have taken about one second / rate
	dur := time.Since(now)
	dur *= 300
	diff := 1*time.Second - dur
	if diff > 30*time.Millisecond {
		t.Fatal("expected second +- 30ms to recover; got  ", dur)
	}
}

func TestRate(t *testing.T) {
	b := tokenbucket.New(1, 5000, 2500)
	now := time.Now()
	passed := 0
	for time.Since(now) < 1*time.Second {
		if b.Touch(nil) {
			passed += 1
		}
	}
	// we allow the burst at the start of the second,
	// then settle down into the actual rate.
	// Fudge term of 10 since we can't be sure that it's
	// an actual second that we loop for.
	if passed < 7490 || passed > 7510 {
		t.Fatal("expected 7500 touches through; got ", passed)
	}
}
