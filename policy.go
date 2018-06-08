// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package forwardproxy

import (
	"hash/fnv"
	"math/rand"
	"net"
	"net/http"
	"sync"
)

// HostPool is a collection of Outgoing IP addresses.
type HostPool []string

// Policy decides how an address will be selected from a pool.
type Policy interface {
	Select(pool HostPool, r *http.Request) string
}

func init() {
	RegisterPolicy("random", func(arg string) Policy { return &Random{} })
	RegisterPolicy("round_robin", func(arg string) Policy { return &RoundRobin{} })
	RegisterPolicy("ip_hash", func(arg string) Policy { return &IPHash{} })
}

// Random is a policy that selects an address from a pool at random.
type Random struct{}

// Select selects an an address at random from the specified pool.
func (r *Random) Select(pool HostPool, request *http.Request) string {

	var randHost string
	count := 0
	for _, host := range pool {

		count++
		if (rand.Int() % count) == 0 {
			randHost = host
		}
	}
	return randHost
}

// RoundRobin is a policy that selects an address based on round-robin ordering.
type RoundRobin struct {
	robin uint32
	mutex sync.Mutex
}

// Select selects an an address from the pool using a round-robin ordering scheme.
func (r *RoundRobin) Select(pool HostPool, request *http.Request) string {
	poolLen := uint32(len(pool))
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// Return next available host
	for i := uint32(0); i < poolLen; i++ {
		r.robin++
		host := pool[r.robin%poolLen]
		return host
	}
	return "127.0.0.1"
}

// hostByHashing returns an address from pool based on a hashable string
func hostByHashing(pool HostPool, s string) string {
	poolLen := uint32(len(pool))
	index := hash(s) % poolLen
	for i := uint32(0); i < poolLen; i++ {
		index += i
		host := pool[index%poolLen]
		return host
	}
	return "127.0.0.1"
}

// hash calculates a hash based on string s
func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// IPHash is a policy that selects an address based on hashing the request IP
type IPHash struct{}

// Select selects an an address from the pool based on hashing the request and destination IP
func (r *IPHash) Select(pool HostPool, request *http.Request) string {
	clientIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		clientIP = request.RemoteAddr
	}
	remoteIP, _, err := net.SplitHostPort(request.Host)
	if err != nil {
		remoteIP = request.Host
	}
	return hostByHashing(pool, clientIP+remoteIP)
}
