// Copyright (c) 2013 CloudFlare, Inc.

package main

import (
	vcache "github.com/youtube/vitess/go/cache"
)

type VCache struct {
	vcache.LRUCache
}

func NewVCache(capacity uint64) *VCache {
	return &VCache{
		LRUCache: *vcache.NewLRUCache(capacity),
	}
}

type Value struct {
	v string
}

func (*Value) Size() int {
	return 1
}

func (c *VCache) Get(key string) (string, bool) {
	v, ok := c.LRUCache.Get(key)
	if !ok {
		return "", false
	}
	return v.(*Value).v, ok
}

func (c *VCache) Set(key, value string) {
	c.LRUCache.Set(key, &Value{v: value})
}
