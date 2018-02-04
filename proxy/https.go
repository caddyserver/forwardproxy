// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/cloudflare/golibs/lrucache"
)

func HTTPS(network, addr string, auth *Auth, forward Dialer, resolver Resolver) (Dialer, error) {
	var hostname string

	if host, _, err := net.SplitHostPort(addr); err == nil {
		hostname = host
	} else {
		hostname = addr
		addr = net.JoinHostPort(addr, "443")
	}

	s := &https{
		network:  network,
		addr:     addr,
		hostname: hostname,
		forward:  forward,
		resolver: resolver,
		cache:    lrucache.NewLRUCache(128),
	}
	if auth != nil {
		s.user = auth.User
		s.password = auth.Password
	}

	return s, nil
}

type https struct {
	user, password string
	network, addr  string
	hostname       string
	forward        Dialer
	resolver       Resolver
	cache          lrucache.Cache
}

// Dial connects to the address addr on the network net via the HTTPS proxy.
func (h *https) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for HTTP proxy connections of type " + network)
	}

	conn0, err := h.forward.Dial(h.network, h.addr)
	if err != nil {
		return nil, err
	}
	closeConn0 := &conn0
	defer func() {
		if closeConn0 != nil {
			(*closeConn0).Close()
		}
	}()

	var config *tls.Config
	if v, ok := h.cache.GetNotStale(h.addr); ok {
		config = v.(*tls.Config)
	} else {
		config = &tls.Config{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
			ServerName:         h.hostname,
			ClientSessionCache: tls.NewLRUClientSessionCache(1024),
		}
		h.cache.Set(h.addr, config, time.Now().Add(2*time.Hour))
	}

	conn1 := tls.Client(conn0, config)

	err = conn1.Handshake()
	if err != nil {
		return nil, err
	}

	var conn net.Conn = conn1

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

	if h.resolver != nil {
		hosts, err := h.resolver.LookupHost(host)
		if err == nil && len(hosts) > 0 {
			host = hosts[0]
		}
	}

	b := bufPool.Get().(*bytes.Buffer)
	b.Reset()

	fmt.Fprintf(b, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n", host, portStr, host, portStr)
	if h.user != "" {
		fmt.Fprintf(b, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(h.user+":"+h.password)))
	}
	io.WriteString(b, "\r\n")

	bb := b.Bytes()
	bufPool.Put(b)

	if _, err := conn.Write(bb); err != nil {
		return nil, errors.New("proxy: failed to write greeting to HTTP proxy at " + h.addr + ": " + err.Error())
	}

	buf := make([]byte, 2048)
	b0 := buf
	total := 0

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		total += n
		buf = buf[n:]

		if i := bytes.Index(b0, CRLFCRLF); i > 0 {
			conn = &preReaderConn{conn, b0[i+4 : total]}
			b0 = b0[:i+4]
			break
		}
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b0)), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("proxy: failed to read greeting from HTTP proxy at " + h.addr + ": " + resp.Status)
	}

	closeConn0 = nil
	return conn, nil
}
