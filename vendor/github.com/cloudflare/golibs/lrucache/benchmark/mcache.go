// Copyright (c) 2013 CloudFlare, Inc.

package main

import (
	"github.com/cloudflare/golibs/lrucache"
	"time"
)

func makeLRUCache(capacity uint64) lrucache.Cache {
	return lrucache.NewLRUCache(uint(capacity))
}
func makeMultiLRU(capacity uint64) lrucache.Cache {
	shards := uint(2)
	return lrucache.NewMultiLRUCache(shards, uint(capacity)/shards)
}

type MCache struct {
	lrucache.Cache
	expiry time.Time
	now    time.Time
}

type makeCache func(capacity uint64) lrucache.Cache

func NewMCache(capacity uint64, newCache makeCache) *MCache {
	return &MCache{
		Cache:  newCache(capacity),
		expiry: time.Now().Add(time.Duration(30 * time.Second)),
		now:    time.Now(),
	}
}

func (c *MCache) Get(key string) (string, bool) {
	v, ok := c.Cache.Get(key)
	if !ok {
		return "", false
	}
	return v.(*Value).v, true
}

func (c *MCache) Set(key, value string) {
	c.Cache.Set(key, &Value{v: value}, time.Time{})
}
