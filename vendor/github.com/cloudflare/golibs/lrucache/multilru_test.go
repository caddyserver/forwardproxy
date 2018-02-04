// Copyright (c) 2013 CloudFlare, Inc.

package lrucache

import (
	"runtime"
	"testing"
	"time"
)

func TestMultiLRUBasic(t *testing.T) {
	t.Parallel()

	m := NewMultiLRUCache(2, 3)

	if m.Capacity() != 6 {
		t.Error("expecting different capacity")
	}

	m.Set("a", "va", time.Time{})
	m.Set("b", "vb", time.Time{})
	m.Set("c", "vc", time.Time{})

	if m.Len() != 3 {
		t.Error("expecting different length")
	}

	m.Set("a", "va", time.Time{})
	m.Set("b", "vb", time.Time{})
	m.Set("c", "vc", time.Time{})

	if m.Len() != 3 {
		t.Error("expecting different length")
	}

	// chances of all of them going to single bucket are slim
	for c := 'a'; c < 'z'; c = rune(int(c) + 1) {
		m.Set(string(c), string([]rune{'v', c}), time.Time{})
	}
	past := time.Now().Add(time.Duration(-10 * time.Second))
	m.Set("j", "vj", past)

	if m.Len() != 6 {
		t.Error("expecting different length")
	}

	if m.ExpireNow(past) != 0 {
		t.Error("expecting different expire")
	}

	if m.Expire() != 1 {
		t.Error("expecting different expire")
	}

	if m.Clear() != 5 {
		t.Error("expecting different length")
	}

	if m.Len() != 0 {
		t.Error("expecting different length")
	}

	m.Set("a", "va", time.Time{})
	if v, _ := m.Del("a"); v != "va" {
		t.Error("expected hit")
	}
	if _, ok := m.Del("a"); ok {
		t.Error("expected miss")
	}

	// This is stupid, mostly for code coverage.
	m.Clear()
	for c := 'a'; c < 'z'; c = rune(int(c) + 1) {
		m.Set(string(c), string([]rune{'v', c}), time.Time{})
	}

	m.SetNow("yy", "vyy", past, past)
	m.SetNow("zz", "vzz", time.Time{}, time.Now())

	m.GetQuiet("yy")
	m.GetQuiet("yy")

	m.SetNow("yy", "vyy", past, past)
	if v, _ := m.Get("yy"); v != "vyy" {
		t.Error("expected hit")
	}

	if v, _ := m.GetNotStaleNow("yy", past); v != "vyy" {
		t.Error("expected hit")
	}

	if _, ok := m.GetNotStale("yy"); ok {
		t.Error("expected miss")
	}
}

func filledMultiLRU(expire time.Time) *MultiLRUCache {
	b := NewMultiLRUCache(4, 250)
	for i := 0; i < 1000; i++ {
		b.Set(randomString(2), "value", expire)
	}
	return b
}

func BenchmarkConcurrentGetMultiLRU(bb *testing.B) {
	b := filledMultiLRU(time.Now().Add(time.Duration(4)))

	cpu := runtime.GOMAXPROCS(0)
	ch := make(chan bool)
	worker := func() {
		for i := 0; i < bb.N/cpu; i++ {
			b.Get(randomString(2))
		}
		ch <- true
	}
	for i := 0; i < cpu; i++ {
		go worker()
	}
	for i := 0; i < cpu; i++ {
		_ = <-ch
	}
}

func BenchmarkConcurrentSetMultiLRU(bb *testing.B) {
	b := filledMultiLRU(time.Now().Add(time.Duration(4)))

	cpu := runtime.GOMAXPROCS(0)
	ch := make(chan bool)
	worker := func() {
		for i := 0; i < bb.N/cpu; i++ {
			expire := time.Now().Add(time.Duration(4 * time.Second))
			b.Set(randomString(2), "v", expire)
		}
		ch <- true
	}
	for i := 0; i < cpu; i++ {
		go worker()
	}
	for i := 0; i < cpu; i++ {
		_ = <-ch
	}
}

// No expiry
func BenchmarkConcurrentSetNXMultiLRU(bb *testing.B) {
	b := filledMultiLRU(time.Time{})

	cpu := runtime.GOMAXPROCS(0)
	ch := make(chan bool)
	worker := func() {
		for i := 0; i < bb.N/cpu; i++ {
			b.Set(randomString(2), "v", time.Time{})
		}
		ch <- true
	}
	for i := 0; i < cpu; i++ {
		go worker()
	}
	for i := 0; i < cpu; i++ {
		_ = <-ch
	}
}
