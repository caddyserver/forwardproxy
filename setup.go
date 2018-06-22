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
	"os"
)

func setup(c *caddy.Controller) error {
	httpserver.GetConfig(c).FallbackSite = true
	fp := &ForwardProxy{
		dialTimeout: time.Second * 20,
		hostname:    httpserver.GetConfig(c).Host(), port: httpserver.GetConfig(c).Port(),
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
			if len(args) != 2 {
				return c.ArgErr()
			}
			if len(args[0]) == 0 {
				return c.Err("empty usernames are not allowed")
			}
			// TODO: Evaluate policy of allowing empty passwords.
			if strings.Contains(args[0], ":") {
				return c.Err("character ':' in usernames is not allowed")
			}
			if fp.authCredentials == nil {
				fp.authCredentials = [][]byte{}
			}
			// base64-encode credentials
			buf := make([]byte, base64.StdEncoding.EncodedLen(len(args[0])+1+len(args[1])))
			base64.StdEncoding.Encode(buf, []byte(args[0]+":"+args[1]))
			fp.authCredentials = append(fp.authCredentials, buf)
			fp.authRequired = true
		case "ports":
			if len(args) == 0 {
				return c.ArgErr()
			}
			if len(fp.whitelistedPorts) != 0 {
				return c.Err("ports subdirective specified twice")
			}
			fp.whitelistedPorts = make([]int, len(args))
			for i, p := range args {
				intPort, err := strconv.Atoi(p)
				if intPort <= 0 || intPort > 65535 || err != nil {
					return c.Err("ports are expected to be space-separated" +
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
				return c.Err("serve_pac subdirective specified twice")
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
				return c.Err("response_timeout cannot be negative.")
			}
			responseTimeout := time.Duration(timeout) * time.Second
			fp.responseTimeout = &responseTimeout
		case "dial_timeout":
			if len(args) != 1 {
				return c.ArgErr()
			}
			timeout, err := strconv.Atoi(args[0])
			if err != nil {
				return c.ArgErr()
			}
			if timeout < 0 {
				return c.Err("dial_timeout cannot be negative.")
			}
			fp.dialTimeout = time.Second * time.Duration(timeout)
		case "upstream":
			if len(args) != 1 {
				return c.ArgErr()
			}
			fp.upstream = args[0]
		case "acl":
			if len(args) != 0 {
				return c.Err("acl should be only subdirective on the line")
			}
			args := c.RemainingArgs()
			if len(args) > 0 {
				return c.ArgErr()
			}
			c.Next()
			if c.Val() != "{" {
				return c.Err("acl directive must be followed by opening curly braces \"{\"")
			}
			for {
				if !c.Next() {
					return c.Err("acl blockmust be ended by closing curly braces \"}\"")
				}
				aclDirective := c.Val()
				args := c.RemainingArgs()
				if aclDirective == "}" {
					break
				}
				if len(args) == 0 {
					return c.ArgErr()
				}
				var ruleSubjects []string
				var err error
				aclAllow := false
				switch aclDirective {
				case "allow":
					ruleSubjects = args[:]
					aclAllow = true
				case "allowfile":
					if len(args) != 1 {
						return c.Err("allowfile accepts a single filename argument")
					}
					ruleSubjects, err = readLinesFromFile(args[0])
					if err != nil {
						return err
					}
					aclAllow = true
				case "deny":
					ruleSubjects = args[:]
				case "denyfile":
					if len(args) != 1 {
						return c.Err("denyfile accepts a single filename argument")
					}
					ruleSubjects, err = readLinesFromFile(args[0])
					if err != nil {
						return err
					}
				default:
					return c.Err("expected acl directive: allow/allowfile/deny/denyfile." +
						"got: " + aclDirective)
				}
				for _, rs := range ruleSubjects {
					ar, err := newAclRule(rs, aclAllow)
					if err != nil {
						return err
					}
					fp.aclRules = append(fp.aclRules, ar)
				}
			}
		default:
			return c.ArgErr()
		}
	}

	if fp.upstream != "" && (fp.aclRules != nil || len(fp.whitelistedPorts) != 0) {
		return c.Err("upstream subdirective is incompatible with acl/ports subdirectives")
	}

	for _, ipDeny := range []string{
		"10.0.0.0/8",
		"127.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fe80::/10",
	} {
		ar, err := newAclRule(ipDeny, false)
		if err != nil {
			panic(err)
		}
		fp.aclRules = append(fp.aclRules, ar)
	}
	fp.aclRules = append(fp.aclRules, &aclAllRule{allow: true})

	if fp.probeResistEnabled {
		if !fp.authRequired {
			return c.Err("probing resistance requires authentication: " +
				"add `basicauth username password` to forwardproxy")
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

	fp.dial = dialer.Dial

	if fp.upstream != "" {
		upstreamURL, err := url.Parse(fp.upstream)
		if err != nil {
			return errors.New("failed to parse upstream address: " + err.Error())
		}

		if !isLocalhost(upstreamURL.Hostname()) && upstreamURL.Scheme != "https" {
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
		if isLocalhost(upstream.Hostname()) {
			log.Println("Localhost upstream detected, disabling verification of TLS certificate")
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

func isLocalhost(hostname string) bool {
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return true
	}
	return false
}

func readLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hostnames []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hostnames = append(hostnames, scanner.Text())
	}

	return hostnames, scanner.Err()
}

// isValidDomainLite shamelessly rejects non-LDH names. returns nil if domains seems valid
func isValidDomainLite(domain string) error {
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || '0' <= c && c <= '9' ||
			c == '-' || c == '.' {
			continue
		}
		return errors.New("character " + string(c) + " is not allowed")
	}
	sections := strings.Split(domain, ".")
	for _, s := range sections {
		if len(s) == 0 {
			return errors.New("empty section between dots in domain name or trailing dot")
		}
		if len(s) > 63 {
			return errors.New("domain name section is too long")
		}
	}
	return nil
}
