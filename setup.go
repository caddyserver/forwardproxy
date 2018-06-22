// Copyright 2017 Google Inc.
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

package forwardproxy

import (
	"encoding/base64"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"bufio"
	"crypto/tls"
	"fmt"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"golang.org/x/net/proxy"
)

func setup(c *caddy.Controller) error {
	httpserver.GetConfig(c).FallbackSite = true
	fp := &ForwardProxy{dialTimeout: time.Second * 20,
		hostname: httpserver.GetConfig(c).Host(), port: httpserver.GetConfig(c).Port(),
		httpTransport: http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}}
	fp.httpTransport.DialTLS = func(network, addr string) (net.Conn, error) {
		return nil, &http.ProtocolError{ErrorString: "Proxy does not fetch TLS resources, use CONNECT instead"}
	}

	c.Next() // skip the directive name

	args := c.RemainingArgs()
	if len(args) > 0 {
		return c.ArgErr()
	}

	for c.NextBlock() {
		subdirective := c.Val()
		args := c.RemainingArgs()
		switch subdirective {
		case "basicauth":
			var user string
			var pass string
			switch len(args) {
			case 1:
				user = args[0]
			case 2:
				user = args[0]
				pass = args[1]
			default:
				return c.ArgErr()
			}
			if len(user) == 0 {
				return errors.New("Parse error: empty usernames are not allowed")
			}
			if strings.Contains(user, ":") {
				return errors.New("Parse error: character ':' in usernames is not allowed")
			}
			if fp.authCredentials == nil {
				fp.authCredentials = [][]byte{}
			}
			// base64-encode credentials
			buf := make([]byte, base64.StdEncoding.EncodedLen(len(user)+1+len(pass)))
			base64.StdEncoding.Encode(buf, []byte(user+":"+pass))
			fp.authCredentials = append(fp.authCredentials, buf)
			fp.authRequired = true
		case "ports":
			if len(args) == 0 {
				return c.ArgErr()
			}
			if len(fp.whitelistedPorts) != 0 {
				return errors.New("Parse error: ports subdirective specified twice")
			}
			fp.whitelistedPorts = make([]int, len(args))
			for i, p := range args {
				intPort, err := strconv.Atoi(p)
				if intPort <= 0 || intPort > 65535 || err != nil {
					return errors.New("Parse error: ports are expected to be space-separated" +
						" and in 0-65535 range. Got: " + p)
				}
				fp.whitelistedPorts[i] = intPort
			}
		case "hide_ip":
			if len(args) != 0 {
				return c.ArgErr()
			}
			fp.hideIP = true
		case "hide_via":
			if len(args) != 0 {
				return c.ArgErr()
			}
			fp.hideVia = true
		case "probe_resistance":
			if len(args) > 1 {
				return c.ArgErr()
			}
			fp.probeResistEnabled = true
			if len(args) == 1 {
				lowercaseArg := strings.ToLower(args[0])
				if lowercaseArg != args[0] {
					log.Println("WARNING: secret domain appears to have uppercase letters in it, which are not visitable")
				}
				fp.probeResistDomain = args[0]
			}
		case "serve_pac":
			if len(args) > 1 {
				return c.ArgErr()
			}
			if len(fp.pacFilePath) != 0 {
				return errors.New("Parse error: serve_pac subdirective specified twice")
			}
			if len(args) == 1 {
				fp.pacFilePath = args[0]
				if !strings.HasPrefix(fp.pacFilePath, "/") {
					fp.pacFilePath = "/" + fp.pacFilePath
				}
			} else {
				fp.pacFilePath = "/proxy.pac"
			}
			log.Printf("Proxy Auto-Config will be served at %s%s\n", fp.hostname, fp.pacFilePath)
		case "response_timeout":
			if len(args) != 1 {
				return c.ArgErr()
			}
			timeout, err := strconv.Atoi(args[0])
			if err != nil {
				return c.ArgErr()
			}
			if timeout < 0 {
				return errors.New("Parse error: response_timeout cannot be negative.")
			}
			fp.httpTransport.ResponseHeaderTimeout = time.Second * time.Duration(timeout)
		case "dial_timeout":
			if len(args) != 1 {
				return c.ArgErr()
			}
			timeout, err := strconv.Atoi(args[0])
			if err != nil {
				return c.ArgErr()
			}
			if timeout < 0 {
				return errors.New("Parse error: dial_timeout cannot be negative.")
			}
			fp.dialTimeout = time.Second * time.Duration(timeout)
		case "upstream":
			if len(args) != 1 {
				return c.ArgErr()
			}
			fp.upstream = args[0]
		default:
			return c.ArgErr()
		}
	}

	if fp.probeResistEnabled {
		if !fp.authRequired {
			return errors.New("Parse error: probing resistance requires authentication")
		}
		if len(fp.probeResistDomain) > 0 {
			log.Printf("Secret domain used to connect to proxy: %s\n", fp.probeResistDomain)
		}
	}

	dialer := &net.Dialer{
		Timeout:   fp.dialTimeout,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	if fp.upstream != "" {
		upstreamURL, err := url.Parse(fp.upstream)
		if err != nil {
			return errors.New("failed to parse upstream address: " + err.Error())
		}

		if !isLocalhost(upstreamURL) && upstreamURL.Scheme != "https" {
			return errors.New("insecure schemes are only allowed to localhost upstreams")
		}

		// TODO: remove homebrewed Dialer when https://go-review.googlesource.com/c/net/+/111135 gets merged
		proxy.RegisterDialerType("https", func(u *url.URL, _ proxy.Dialer) (proxy.Dialer, error) {
			// CONNECT request is proxied as-is, so we don't care about target url, but it could be
			// useful in future to implement policies of choosing between multiple upstream servers.
			// Given dialer is not used, since it's the same dialer provided by us.
			return NewHTTPDialer(dialer, true, upstreamURL), nil
		})
		proxy.RegisterDialerType("http", func(u *url.URL, _ proxy.Dialer) (proxy.Dialer, error) {
			return NewHTTPDialer(dialer, false, upstreamURL), nil
		})
		newDialer, err := proxy.FromURL(upstreamURL, dialer)
		if err != nil {
			return errors.New("failed to create proxy to upstream: " + err.Error())
		}
		fp.dial = newDialer.Dial
		fp.httpTransport.Dial = newDialer.Dial
	} else {
		fp.dial = dialer.Dial
		fp.httpTransport.DialContext = dialer.DialContext
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		fp.Next = next
		return fp
	})

	makeBuffer := func() interface{} { return make([]byte, 0, 32*1024) }
	bufferPool = sync.Pool{New: makeBuffer}
	return nil
}

func init() {
	caddy.RegisterPlugin("forwardproxy", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

type HTTPDialer struct {
	dialer       *net.Dialer
	upstreamUrl  string
	tlsConf      *tls.Config
	extraHeaders string // empty or whole lines together with \r\n\r\n
}

func NewHTTPDialer(dialer *net.Dialer, useHTTPS bool, upstream *url.URL) *HTTPDialer {
	d := &HTTPDialer{
		dialer:      dialer,
		upstreamUrl: upstream.Host,
		tlsConf:     nil,
	}
	if useHTTPS {
		d.tlsConf = &tls.Config{ServerName: upstream.Hostname()}
		if isLocalhost(upstream) {
			log.Println("Localhost upstream detected, disabling verification of TLS ceritifcate")
			d.tlsConf.InsecureSkipVerify = true
		}
	}
	if upstream.User != nil {
		d.extraHeaders = fmt.Sprintf("Proxy-Authorization: basic %s\r\n",
			base64.StdEncoding.EncodeToString([]byte(upstream.User.String())))
	}

	return d
}

func (d *HTTPDialer) Dial(network, addr string) (net.Conn, error) {
	var err error
	var c net.Conn
	if d.tlsConf == nil {
		c, err = d.dialer.Dial(network, d.upstreamUrl)
	} else {
		c, err = tls.DialWithDialer(d.dialer, network, d.upstreamUrl, d.tlsConf)
	}
	if err != nil {
		return nil, err
	}
	// TODO: multiplexed http/2 to upstream, also will eventually be added to x/net/proxy
	_, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", addr, addr, d.extraHeaders)
	if err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Upstream responded with " + resp.Status)
	}
	return c, nil
}

func isLocalhost(u *url.URL) bool {
	if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" ||
		u.Hostname() == "::1" {
		return true
	}
	return false
}
