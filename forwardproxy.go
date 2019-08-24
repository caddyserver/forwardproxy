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
//
// Caching is purposefully ignored.
package forwardproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"github.com/caddyserver/forwardproxy/httpclient"
)

type ForwardProxy struct {
	Next httpserver.Handler

	authRequired    bool
	authCredentials [][]byte // slice with base64-encoded credentials

	hideIP  bool
	hideVia bool

	pacFilePath string

	hostname string // do not intercept requests to the hostname (except for hidden link)
	port     string // port on which chain with forwardproxy is listening on

	probeResistDomain  string
	probeResistEnabled bool

	dialTimeout time.Duration // for initial tcp connection

	httpTransport http.Transport

	// overridden dialContext allow to redirect requests to upstream proxy
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
	upstream    *url.URL // address of upstream proxy

	aclRules         []aclRule
	whitelistedPorts []int
}

var bufferPool sync.Pool

func (fp *ForwardProxy) hostIsAllowed(hostname string, ip net.IP) bool {
	for _, rule := range fp.aclRules {
		switch rule.tryMatch(ip, hostname) {
		case aclDecisionDeny:
			return false
		case aclDecisionAllow:
			return true
		}
	}
	fmt.Println("ERROR: no acl match for ", hostname, ip) // shouldn't happen
	return false
}

func (fp *ForwardProxy) portIsAllowed(port string) bool {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if portInt <= 0 || portInt > 65535 {
		return false
	}
	if len(fp.whitelistedPorts) == 0 {
		return true
	}
	isAllowed := false
	for _, p := range fp.whitelistedPorts {
		if p == portInt {
			isAllowed = true
			break
		}
	}
	return isAllowed
}

// Copies data target->clientReader and clientWriter->target, and flushes as needed
// Returns when clientWriter-> target stream is done.
// Caddy should finish writing target -> clientReader.
func dualStream(target net.Conn, clientReader io.ReadCloser, clientWriter io.Writer) error {
	stream := func(w io.Writer, r io.Reader) error {
		// copy bytes from r to w
		buf := bufferPool.Get().([]byte)
		buf = buf[0:cap(buf)]
		_, _err := flushingIoCopy(w, r, buf)
		if closeWriter, ok := w.(interface {
			CloseWrite() error
		}); ok {
			closeWriter.CloseWrite()
		}
		return _err
	}

	go stream(target, clientReader)
	return stream(clientWriter, target)
}

// Hijacks the connection from ResponseWriter, writes the response and proxies data between targetConn
// and hijacked connection.
func serveHijack(w http.ResponseWriter, targetConn net.Conn) (int, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return http.StatusInternalServerError, errors.New("ResponseWriter does not implement Hijacker")
	}
	clientConn, bufReader, err := hijacker.Hijack()
	if err != nil {
		return http.StatusInternalServerError, errors.New("failed to hijack: " + err.Error())
	}
	defer clientConn.Close()
	// bufReader may contain unprocessed buffered data from the client.
	if bufReader != nil {
		// snippet borrowed from `proxy` plugin
		if n := bufReader.Reader.Buffered(); n > 0 {
			rbuf, err := bufReader.Reader.Peek(n)
			if err != nil {
				return http.StatusBadGateway, err
			}
			targetConn.Write(rbuf)
		}
	}
	// Since we hijacked the connection, we lost the ability to write and flush headers via w.
	// Let's handcraft the response and send it manually.
	res := &http.Response{StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	res.Header.Set("Server", "Caddy")

	err = res.Write(clientConn)
	if err != nil {
		return http.StatusInternalServerError, errors.New("failed to send response to client: " + err.Error())
	}

	return 0, dualStream(targetConn, clientConn, clientConn)
}

// Returns nil error on successful credentials check.
func (fp *ForwardProxy) checkCredentials(r *http.Request) error {
	pa := strings.Split(r.Header.Get("Proxy-Authorization"), " ")
	if len(pa) != 2 {
		return errors.New("Proxy-Authorization is required! Expected format: <type> <credentials>")
	}
	if strings.ToLower(pa[0]) != "basic" {
		return errors.New("Auth type is not supported")
	}
	for _, creds := range fp.authCredentials {
		if subtle.ConstantTimeCompare(creds, []byte(pa[1])) == 1 {
			// Please do not consider this to be timing-attack-safe code. Simple equality is almost
			// mindlessly substituted with constant time algo and there ARE known issues with this code,
			// e.g. size of smallest credentials is guessable. TODO: protect from all the attacks! Hash?
			return nil
		}
	}
	return errors.New("Invalid credentials")
}

// borrowed from `proxy` plugin
func stripPort(address string) string {
	// Keep in mind that the address might be a IPv6 address
	// and thus contain a colon, but not have a port.
	portIdx := strings.LastIndex(address, ":")
	ipv6Idx := strings.LastIndex(address, "]")
	if portIdx > ipv6Idx {
		address = address[:portIdx]
	}
	return address
}

func serveHiddenPage(w http.ResponseWriter, authErr error) (int, error) {
	const hiddenPage = `<html>
<head>
  <title>Hidden Proxy Page</title>
</head>
<body>
<h1>Hidden Proxy Page!</h1>
%s<br/>
</body>
</html>`
	const AuthFail = "Please authenticate yourself to the proxy."
	const AuthOk = "Congratulations, you are successfully authenticated to the proxy! Go browse all the things!"

	w.Header().Set("Content-Type", "text/html")
	if authErr != nil {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Caddy Secure Web Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		w.Write([]byte(fmt.Sprintf(hiddenPage, AuthFail)))
		return 0, authErr
	}
	w.Write([]byte(fmt.Sprintf(hiddenPage, AuthOk)))
	return 0, nil
}

func (fp *ForwardProxy) shouldServePacFile(r *http.Request) bool {
	if len(fp.pacFilePath) > 0 && r.URL.Path == fp.pacFilePath {
		return true
	}
	return false
}

const pacFile = `
function FindProxyForURL(url, host) {
	if (host === "127.0.0.1" || host === "::1" || host === "localhost")
		return "DIRECT";
	return "HTTPS %s:%s";
}
`

func (fp *ForwardProxy) servePacFile(w http.ResponseWriter) (int, error) {
	fmt.Fprintf(w, pacFile, fp.hostname, fp.port)
	return 0, nil
}

// dialContextCheckACL enforces Access Control List and calls fp.DialContext
func (fp *ForwardProxy) dialContextCheckACL(ctx context.Context, network, hostPort string) (net.Conn, *ProxyError) {
	var conn net.Conn

	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, &ProxyError{S: "Network " + network + " is not supported", Code: http.StatusBadRequest}
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, &ProxyError{S: err.Error(), Code: http.StatusBadRequest}
	}

	if fp.upstream != nil {
		// if upstreaming -- do not resolve locally nor check acl
		conn, err = fp.dialContext(ctx, network, hostPort)
		if err != nil {
			return conn, &ProxyError{S: err.Error(), Code: http.StatusBadGateway}
		}
		return conn, nil
	}

	if !fp.portIsAllowed(port) {
		return nil, &ProxyError{S: "port " + port + " is not allowed", Code: http.StatusForbidden}
	}

	// in case IP was provided, net.LookupIP will simply return it
	IPs, err := net.LookupIP(host)
	if err != nil {
		return nil, &ProxyError{S: fmt.Sprintf("Lookup of %s failed: %v", host, err),
			Code: http.StatusBadGateway}
	}

	// This is net.Dial's default behavior: if the host resolves to multiple IP addresses,
	// Dial will try each IP address in order until one succeeds
	for _, ip := range IPs {
		if !fp.hostIsAllowed(host, ip) {
			continue
		}

		conn, err = fp.dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, &ProxyError{S: "No allowed IP addresses for " + host, Code: http.StatusForbidden}
}

func (fp *ForwardProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	var authErr error
	if fp.authRequired {
		authErr = fp.checkCredentials(r)
	}
	if fp.probeResistEnabled && len(fp.probeResistDomain) > 0 && stripPort(r.Host) == fp.probeResistDomain {
		return serveHiddenPage(w, authErr)
	}
	if stripPort(r.Host) == fp.hostname && (r.Method != http.MethodConnect || authErr != nil) {
		// Always pass non-CONNECT requests to hostname
		// Pass CONNECT requests only if probe resistance is enabled and not authenticated
		if fp.shouldServePacFile(r) {
			return fp.servePacFile(w)
		}
		return fp.Next.ServeHTTP(w, r)
	}
	if authErr != nil {
		if fp.probeResistEnabled {
			// probe resistance is requested and requested URI does not match secret domain
			httpserver.WriteSiteNotFound(w, r)
			return 0, authErr // current Caddy behavior without forwardproxy
		} else {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Caddy Secure Web Proxy\"")
			return http.StatusProxyAuthRequired, authErr
		}
	}

	if r.ProtoMajor != 1 && r.ProtoMajor != 2 {
		return http.StatusHTTPVersionNotSupported, errors.New("Unsupported HTTP major version: " + strconv.Itoa(r.ProtoMajor))
	}

	ctx := context.Background()
	if !fp.hideIP {
		ctxHeader := make(http.Header)
		for k, v := range r.Header {
			if kL := strings.ToLower(k); kL == "forwarded" || kL == "x-forwarded-for" {
				ctxHeader[k] = v
			}
		}
		ctxHeader.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
		ctx = context.WithValue(ctx, httpclient.ContextKeyHeader{}, ctxHeader)
	}

	if r.Method == http.MethodConnect {
		if r.ProtoMajor == 2 {
			if len(r.URL.Scheme) > 0 || len(r.URL.Path) > 0 {
				return http.StatusBadRequest, errors.New("CONNECT request has :scheme or/and :path pseudo-header fields")
			}
		}

		hostPort := r.URL.Host
		if hostPort == "" {
			hostPort = r.Host
		}
		targetConn, err := fp.dialContextCheckACL(ctx, "tcp", hostPort)
		if err != nil {
			return err.SplitCodeError()
		}
		if targetConn == nil {
			// safest to check both error and targetConn afterwards, in case fp.dial (potentially unstable
			// from x/net/proxy) misbehaves and returns both nil or both non-nil
			return http.StatusForbidden, errors.New("hostname " + r.URL.Hostname() + " is not allowed")
		}
		defer targetConn.Close()

		switch r.ProtoMajor {
		case 1: // http1: hijack the whole flow
			return serveHijack(w, targetConn)
		case 2: // http2: keep reading from "request" and writing into same response
			defer r.Body.Close()
			wFlusher, ok := w.(http.Flusher)
			if !ok {
				return http.StatusInternalServerError, errors.New("ResponseWriter doesn't implement Flusher()")
			}
			w.WriteHeader(http.StatusOK)
			wFlusher.Flush()
			return 0, dualStream(targetConn, r.Body, w)
		default:
			panic("There was a check for http version, yet it's incorrect")
		}
	} else {
		// Scheme has to be appended to avoid `unsupported protocol scheme ""` error.
		// `http://` is used, since this initial request itself is always HTTP, regardless of what client and server
		// may speak afterwards.
		if r.URL.Scheme == "" {
			r.URL.Scheme = "http"
		}
		if r.URL.Host == "" {
			r.URL.Host = r.Host
		}
		r.Proto = "HTTP/1.1"
		r.ProtoMajor = 1
		r.ProtoMinor = 1
		r.RequestURI = ""

		removeHopByHop(r.Header)

		if !fp.hideIP {
			r.Header.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
		}

		// https://tools.ietf.org/html/rfc7230#section-5.7.1
		if !fp.hideVia {
			r.Header.Add("Via", strconv.Itoa(r.ProtoMajor)+"."+strconv.Itoa(r.ProtoMinor)+" caddy")
		}

		var err error
		var response *http.Response
		if fp.upstream == nil {
			// non-upstream request uses httpTransport to reuse connections
			if r.Body != nil &&
				(r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || r.Method == "TRACE") {
				// make sure request is idempotent and could be retried by saving the Body
				// None of those methods are supposed to have body,
				// but we still need to copy the r.Body, even if it's empty
				rBodyBuf, err := ioutil.ReadAll(r.Body)
				if err != nil {
					return http.StatusBadRequest, errors.New("failed to read request Body: " + err.Error())
				}
				r.GetBody = func() (io.ReadCloser, error) {
					return ioutil.NopCloser(bytes.NewReader(rBodyBuf)), nil
				}
				r.Body, _ = r.GetBody()
			}
			response, err = fp.httpTransport.RoundTrip(r)
		} else {
			// Upstream requests don't interact well with Transport: connections could always be
			// reused, but Transport thinks they go to different Hosts, so it spawns tons of
			// useless connections.
			// Just use dialContext, which will multiplex via single connection, if http/2
			if creds := fp.upstream.User.String(); creds != "" {
				// set upstream credentials for the request, if needed
				r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
			}
			if r.URL.Port() == "" {
				r.URL.Host = net.JoinHostPort(r.URL.Host, "80")
			}
			upsConn, err := fp.dialContext(ctx, "tcp", r.URL.Host)
			if err != nil {
				return http.StatusBadGateway, errors.New("failed to dial upstream: " + err.Error())
			}
			err = r.Write(upsConn)
			if err != nil {
				return http.StatusBadGateway, errors.New("failed to write http request: " + err.Error())
			}
			response, err = http.ReadResponse(bufio.NewReader(upsConn), r)
			if err != nil {
				return http.StatusBadGateway, errors.New("failed to read http response: " + err.Error())
			}
		}
		r.Body.Close()
		if response != nil {
			defer response.Body.Close()
		}
		if err != nil {
			if p, ok := err.(*ProxyError); ok {
				return p.SplitCodeError()
			}
			return http.StatusBadGateway, errors.New("failed to read http response: " + err.Error())
		}

		return 0, forwardResponse(w, response)
	}
}

// Removes hop-by-hop headers, and writes response into ResponseWriter.
func forwardResponse(w http.ResponseWriter, response *http.Response) error {
	w.Header().Del("Server") // remove Server: Caddy, append via instead
	w.Header().Add("Via", strconv.Itoa(response.ProtoMajor)+"."+strconv.Itoa(response.ProtoMinor)+" caddy")

	for header, values := range response.Header {
		for _, val := range values {
			w.Header().Add(header, val)
		}
	}
	removeHopByHop(w.Header())
	w.WriteHeader(response.StatusCode)
	buf := bufferPool.Get().([]byte)
	buf = buf[0:cap(buf)]
	_, err := io.CopyBuffer(w, response.Body, buf)
	return err
}

var hopByHopHeaders = []string{
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Upgrade",
	"Connection",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
}

func removeHopByHop(header http.Header) {
	connectionHeaders := header.Get("Connection")
	for _, h := range strings.Split(connectionHeaders, ",") {
		header.Del(strings.TrimSpace(h))
	}
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

// flushingIoCopy is analogous to buffering io.Copy(), but also attempts to flush on each iteration.
// If dst does not implement http.Flusher(e.g. net.TCPConn), it will do a simple io.CopyBuffer().
// Reasoning: http2ResponseWriter will not flush on its own, so we have to do it manually.
func flushingIoCopy(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	flusher, ok := dst.(http.Flusher)
	if !ok {
		return io.CopyBuffer(dst, src, buf)
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			flusher.Flush()
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}
