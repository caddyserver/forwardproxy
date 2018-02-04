// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"errors"
	"io"
	"net"
	"strconv"
)

// SOCKS4 returns a Dialer that makes SOCKSv4 connections to the given address
func SOCKS4(network, addr string, is4a bool, forward Dialer, resolver Resolver) (Dialer, error) {
	s := &socks4{
		network:  network,
		addr:     addr,
		is4a:     is4a,
		forward:  forward,
		resolver: resolver,
	}

	return s, nil
}

type socks4 struct {
	network, addr string
	is4a          bool
	forward       Dialer
	resolver      Resolver
}

const (
	socks4Version        = 4
	socks4Connect        = 1
	socks4Granted        = 0x5a
	socks4Rejected       = 0x5b
	socks4IdentdRequired = 0x5c
	socks4IdentdFailed   = 0x5d
)

var socks4Errors = []string{
	"",
	"connection forbidden",
	"identd required",
	"identd failed",
}

// Dial connects to the address addr on the network net via the SOCKS4 proxy.
func (s *socks4) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4":
	default:
		return nil, errors.New("proxy: no support for SOCKS4 proxy connections of type " + network)
	}

	conn, err := s.forward.Dial(s.network, s.addr)
	if err != nil {
		return nil, err
	}
	closeConn := &conn
	defer func() {
		if closeConn != nil {
			(*closeConn).Close()
		}
	}()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New("proxy: failed to parse port number: " + portStr)
	}
	if port < 1 || port > 0xffff {
		return nil, errors.New("proxy: port number out of range: " + portStr)
	}

	if s.resolver != nil {
		if hosts, err := s.resolver.LookupHost(host); err == nil && len(hosts) > 0 {
			host = hosts[0]
		}
	}

	buf := make([]byte, 0, 1024)

	buf = append(buf, socks4Version, socks4Connect)
	buf = append(buf, byte(port>>8), byte(port))
	if s.is4a {
		buf = append(buf, 0, 0, 0, 1, 0)
		buf = append(buf, []byte(host+"\x00")...)
	} else {
		ip, err := net.ResolveIPAddr("ip4", host)
		if err != nil {
			return nil, err
		}
		ip4 := ip.IP.To4()
		if len(ip4) < 4 {
			return nil, errors.New("proxy: resolve ip address out of range: " + ip.String())
		}
		buf = append(buf, ip4[0], ip4[1], ip4[2], ip4[3], 0)
	}

	_, err = conn.Write(buf)
	if err != nil {
		return nil, err
	}

	var resp [8]byte
	_, err = conn.Read(resp[:])
	if err != nil && err != io.EOF {
		return nil, err
	}

	switch code := resp[1]; code {
	case socks4Granted:
		break
	case socks4Rejected, socks4IdentdRequired, socks4IdentdFailed:
		return nil, errors.New("proxy: SOCKS4 proxy at " + s.addr + " failed to connect: " + socks4Errors[code-socks4Granted])
	default:
		return nil, errors.New("proxy: SOCKS4 proxy at " + s.addr + " failed to connect: errno 0x" + strconv.FormatInt(int64(code), 16))
	}

	closeConn = nil
	return conn, nil
}
