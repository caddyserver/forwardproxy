// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package proxy

import (
	"errors"
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"
)

func SSH2(network, addr string, auth *Auth, forward Dialer, resolver Resolver) (Dialer, error) {
	s := &ssh2{
		network:  network,
		addr:     addr,
		forward:  forward,
		resolver: resolver,
		user:     auth.User,
		password: auth.Password,
	}

	return s, nil
}

type ssh2 struct {
	user, password string
	network, addr  string
	forward        Dialer
	resolver       Resolver
}

type sshConn struct {
	net.Conn
	sshClient *ssh.Client
}

func (c *sshConn) Close() error {
	defer c.sshClient.Close()
	return c.Conn.Close()
}

// Dial connects to the address addr on the network net via the HTTP1 proxy.
func (s *ssh2) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for HTTP proxy connections of type " + network)
	}

	config := &ssh.ClientConfig{
		User: s.user,
		Auth: []ssh.AuthMethod{
			ssh.Password(s.password),
		},
	}

	conn, err := ssh.Dial(s.network, s.addr, config)
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
		hosts, err := s.resolver.LookupHost(host)
		if err == nil && len(hosts) > 0 {
			host = hosts[0]
		}
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	raddr := &net.TCPAddr{IP: ips[0], Port: port}
	conn1, err := conn.DialTCP(network, nil, raddr)
	if err != nil {
		return nil, err
	}

	closeConn = nil
	return &sshConn{conn1, conn}, nil
}
