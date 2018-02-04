// Copyright (c) 2013 CloudFlare, Inc.

// Microbenchmarks for LRUCache, MultiLRUCache versus vitess/cache.
package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"
)

func randomString(l int) string {
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes[i] = byte(65 + rand.Intn(90-65))
	}
	return string(bytes)
}

type GenericCache interface {
	Set(key string, value string)
	Get(key string) (string, bool)
}

func main() {
	list_of_capacities := []uint64{32, 128, 1024, 4096, 1024 * 1024}
	number_of_keys := 30000
	key_length := 3

	keys := make([]string, number_of_keys)
	for i := 0; i < 1000; i++ {
		keys[i] = randomString(key_length)
	}

	for _, capacity := range list_of_capacities {
		m := make([]GenericCache, 3)

		fmt.Printf("[*] Capacity=%v Keys=%v KeySpace=%v\n", capacity, number_of_keys, int(math.Pow(90-65., float64(key_length))))
		fmt.Printf("\t\tvitess\t\tLRUCache\tMultiLRUCache-4\n")

		tc0 := time.Now()
		m[0] = (GenericCache)(NewVCache(capacity))
		tc1 := time.Now()
		m[1] = (GenericCache)(NewMCache(capacity, makeLRUCache))
		tc2 := time.Now()
		m[2] = (GenericCache)(NewMCache(capacity, makeMultiLRU))
		tc3 := time.Now()

		fmt.Printf("create\t\t%-10v\t%-10v\t%v\n", tc1.Sub(tc0), tc2.Sub(tc1), tc3.Sub(tc2))

		fmt.Printf("Get (miss)")
		for _, c := range m {
			t0 := time.Now()
			for i := 0; i < 1000000; i++ {
				c.Get(keys[i%len(keys)])
			}
			td := time.Since(t0)
			fmt.Printf("\t%v", td)
		}
		fmt.Printf("\n")

		fmt.Printf("SetNX #1")
		for _, c := range m {
			t0 := time.Now()
			for i := 0; i < 1000000; i++ {
				c.Set(keys[i%len(keys)], "v")
			}
			td := time.Since(t0)
			fmt.Printf("\t%v", td)
		}
		fmt.Printf("\n")

		fmt.Printf("Get (hit)")
		for _, c := range m {
			t0 := time.Now()
			for i := 0; i < 1000000; i++ {
				c.Get(keys[i%len(keys)])
			}
			td := time.Since(t0)
			fmt.Printf("\t%v", td)
		}
		fmt.Printf("\n")

		fmt.Printf("SetNX #2")
		for _, c := range m {
			t0 := time.Now()
			for i := 0; i < 1000000; i++ {
				c.Set(keys[i%len(keys)], "v")
			}
			td := time.Since(t0)
			fmt.Printf("\t%v", td)
		}
		fmt.Printf("\n\n")
	}
}
