// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

type dummyResolver struct{}

// Direct is a direct proxy: one that makes network connections directly.
var DummyResolver = dummyResolver{}

func (dummyResolver) LookupHost(host string) (addrs []string, err error) {
	return []string{host}, nil
}
