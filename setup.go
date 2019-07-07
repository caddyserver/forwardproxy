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
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/caddyserver/forwardproxy/httpclient"
	"golang.org/x/net/proxy"
)

func setup(c *caddy.Controller) error {
	httpserver.GetConfig(c).FallbackSite = true
	fp := &ForwardProxy{
		dialTimeout: time.Second * 20,
		hostname:    httpserver.GetConfig(c).Host(), port: httpserver.GetConfig(c).Port(),
		httpTransport: http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConns:        50,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
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
			fp.httpTransport.ResponseHeaderTimeout = time.Duration(timeout) * time.Second
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
			if fp.upstream != nil {
				return c.Err("upstream directive specified more than once")
			}
			var err error
			fp.upstream, err = url.Parse(args[0])
			if err != nil {
				return c.Err("failed to parse upstream address: " + err.Error())
			}
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

	if fp.upstream != nil && (fp.aclRules != nil || len(fp.whitelistedPorts) != 0) {
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
	fp.dialContext = dialer.DialContext
	fp.httpTransport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		conn, err := fp.dialContextCheckACL(ctx, network, address)
		if err != nil {
			return conn, err
		}
		return conn, nil
	}

	if fp.upstream != nil {
		if !isLocalhost(fp.upstream.Hostname()) && fp.upstream.Scheme != "https" {
			return errors.New("insecure schemes are only allowed to localhost upstreams")
		}

		registerHTTPDialer := func(u *url.URL, _ proxy.Dialer) (proxy.Dialer, error) {
			// CONNECT request is proxied as-is, so we don't care about target url, but it could be
			// useful in future to implement policies of choosing between multiple upstream servers.
			// Given dialer is not used, since it's the same dialer provided by us.
			d, err := httpclient.NewHTTPConnectDialer(fp.upstream.String())
			if err != nil {
				return nil, err
			}
			d.Dialer = *dialer
			if isLocalhost(fp.upstream.Hostname()) && fp.upstream.Scheme == "https" {
				// disabling verification helps with testing the package and setups
				// either way, it's impossible to have a legit TLS certificate for "127.0.0.1"
				log.Println("Localhost upstream detected, disabling verification of TLS certificate")
				d.DialTLS = func(network string, address string) (net.Conn, string, error) {
					conn, err := tls.Dial(network, address, &tls.Config{InsecureSkipVerify: true})
					if err != nil {
						return nil, "", err
					}
					return conn, conn.ConnectionState().NegotiatedProtocol, nil
				}
			}
			return d, nil
		}
		proxy.RegisterDialerType("https", registerHTTPDialer)
		proxy.RegisterDialerType("http", registerHTTPDialer)

		upstreamDialer, err := proxy.FromURL(fp.upstream, dialer)
		if err != nil {
			return errors.New("failed to create proxy to upstream: " + err.Error())
		}

		if ctxDialer, ok := upstreamDialer.(interface {
			DialContext(ctx context.Context, network, address string) (net.Conn, error)
		}); ok {
			// upstreamDialer has DialContext - use it
			fp.dialContext = ctxDialer.DialContext
		} else {
			// upstreamDialer does not have DialContext - ignore the context :(
			fp.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
				return upstreamDialer.Dial(network, address)
			}
		}
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

type ProxyError struct {
	S    string
	Code int
}

func (e *ProxyError) Error() string {
	return fmt.Sprintf("[%v] %s", e.Code, e.S)
}

func (e *ProxyError) SplitCodeError() (int, error) {
	if e == nil {
		return 200, nil
	}
	return e.Code, errors.New(e.S)
}
