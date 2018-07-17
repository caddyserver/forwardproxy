// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// httpclient is used by the upstreaming forwardproxy to establish connections to http(s) upstreams.
// it implements x/net/proxy.Dialer interface
package httpclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/http2"
)

// HTTPConnectDialer allows to configure one-time use HTTP CONNECT client
type HTTPConnectDialer struct {
	ProxyUrl      url.URL
	DefaultHeader http.Header

	// TODO: If spkiFp is set, use it as SPKI fingerprint to confirm identity of the
	// proxy, instead of relying on standard PKI CA roots
	SpkiFP []byte

	Dialer net.Dialer // overridden dialer allow to control establishment of TCP connection

	// overridden DialTLS allows user to control establishment of TLS connection,
	// given TCP connection. returns established TLS connection, ALPN and error
	DialTLS func(net.Conn) (net.Conn, string, error)
}

// NewHTTPClient creates a client to issue CONNECT requests and tunnel traffic via HTTPS proxy.
// proxyUrlStr must provide Scheme and Host, may provide credentials and port.
// Example: https://username:password@golang.org:443
func NewHTTPConnectDialer(proxyUrlStr string) (*HTTPConnectDialer, error) {
	proxyUrl, err := url.Parse(proxyUrlStr)
	if err != nil {
		return nil, err
	}

	if proxyUrl.Host == "" {
		return nil, errors.New("misparsed `url=`, make sure to specify full url like https://username:password@hostname.com:443/")
	}

	switch proxyUrl.Scheme {
	case "http":
		if proxyUrl.Port() == "" {
			proxyUrl.Host = net.JoinHostPort(proxyUrl.Host, "80")
		}
	case "https":
		if proxyUrl.Port() == "" {
			proxyUrl.Host = net.JoinHostPort(proxyUrl.Host, "443")
		}
	case "":
		return nil, errors.New("specify scheme explicitly (https://)")
	default:
		return nil, errors.New("scheme " + proxyUrl.Scheme + " is not supported")
	}

	client := &HTTPConnectDialer{
		ProxyUrl:      *proxyUrl,
		DefaultHeader: make(http.Header),
		SpkiFP:        nil,
	}

	if proxyUrl.User != nil {
		if proxyUrl.User.Username() != "" {
			password, _ := proxyUrl.User.Password()
			client.DefaultHeader.Set("Proxy-Authorization", "Basic "+
				base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.Username()+":"+password)))
		}
	}
	return client, nil
}

func (c *HTTPConnectDialer) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// Users of context.WithValue should define their own types for keys
type ContextKeyHeader struct{}

// ctx.Value will be inspected for optional ContextKeyHeader{} key, with `http.Header` value,
// which will be added to outgoing request headers, overriding any colliding c.DefaultHeader
func (c *HTTPConnectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	req := (&http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)
	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}
	if ctxHeader, ctxHasHeader := ctx.Value(ContextKeyHeader{}).(http.Header); ctxHasHeader {
		for k, v := range ctxHeader {
			req.Header[k] = v
		}
	}

	rawConn, err := c.Dialer.DialContext(ctx, network, c.ProxyUrl.Host)
	if err != nil {
		return nil, err
	}

	negotiatedProtocol := ""
	switch c.ProxyUrl.Scheme {
	case "http":
	case "https":
		if c.DialTLS != nil {
			rawConn, negotiatedProtocol, err = c.DialTLS(rawConn)
			if err != nil {
				return nil, err
			}
			break
		}
		tlsConf := tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			ServerName: c.ProxyUrl.Hostname(),
		}

		tlsConn := tls.Client(rawConn, &tlsConf)
		err = tlsConn.Handshake()
		if err != nil {
			return nil, err
		}
		negotiatedProtocol = tlsConn.ConnectionState().NegotiatedProtocol
		rawConn = tlsConn
	default:
		return nil, errors.New("scheme " + c.ProxyUrl.Scheme + " is not supported")
	}

	var proxyConn net.Conn

	var resp *http.Response
	switch negotiatedProtocol {
	case "":
		fallthrough
	case "http/1.1":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err = req.Write(rawConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		resp, err = http.ReadResponse(bufio.NewReader(rawConn), req)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		proxyConn = rawConn
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		pr, pw := io.Pipe()
		req.Body = ioutil.NopCloser(pr)

		t := http2.Transport{}
		h2client, err := t.NewClientConn(rawConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		resp, err = h2client.RoundTrip(req)
		if err != nil {
			rawConn.Close()
			return nil, err
		}

		proxyConn = &http2Conn{Conn: rawConn, in: pw, out: resp.Body}
	default:
		rawConn.Close()
		return nil, errors.New("negotiated unsupported application layer protocol: " +
			negotiatedProtocol)
	}

	if resp.StatusCode != http.StatusOK {
		rawConn.Close()
		return nil, errors.New("Proxy responded with non 200 code: " + resp.Status)
	}

	return proxyConn, nil
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	h.out.Close()
	h.in.Close()
	return h.Conn.Close()
}
