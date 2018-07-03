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

// Caching is purposefully ignored. Pipelining is expected to work, but doesn't have to. Might be (ab)used to get
// into internal networks.
package forwardproxy

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
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

	dialTimeout     time.Duration  // for initial tcp connection
	responseTimeout *time.Duration // for getting response (affects GET requests only)

	// overridden dial allows to redirect requests to upstream proxy
	dial     func(network, address string) (net.Conn, error)
	upstream string // address of upstream proxy

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

// Copies data r1->w1 and r2->w2, flushes as needed, and returns when both streams are done.
func dualStream(w1 io.Writer, r1 io.Reader, w2 io.Writer, r2 io.Reader) error {
	errChan := make(chan error)

	stream := func(w io.Writer, r io.Reader) {
		buf := bufferPool.Get().([]byte)
		buf = buf[0:cap(buf)]
		_, _err := flushingIoCopy(w, r, buf)
		errChan <- _err
	}

	go stream(w1, r1)
	go stream(w2, r2)

	firstHangerErr := <-errChan

	closeTimeout := time.NewTimer(30 * time.Second)
	select {
	case _ = <-errChan:
	case <-closeTimeout.C:
	}
	closeTimeout.Stop()
	return firstHangerErr
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

	return 0, dualStream(targetConn, clientConn, clientConn, targetConn)
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
		w.Header().Set("Proxy-Authenticate", "Basic")
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

// bool indicates whether it was rejected as "Forbidden"
// TODO: after custom status code-based errors are implemented package-wide, remove the bool
func (fp *ForwardProxy) dialRequestedAddress(r *http.Request) (net.Conn, error, bool) {
	var err error
	var conn net.Conn

	hostPort := r.URL.Host
	if hostPort == "" {
		hostPort = r.Host
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		if r.Method == http.MethodConnect {
			return nil, err, false
		}
		// for other methods, try implicit port 80
		hostPort = net.JoinHostPort(hostPort, "80")
		host, port, err = net.SplitHostPort(hostPort)
		if err != nil {
			return nil, err, false
		}
	}
	if fp.upstream != "" {
		// if upstreaming -- do not resolve locally nor check acl
		conn, err = fp.dial("tcp", hostPort)
		return conn, err, false
	}

	if !fp.portIsAllowed(port) {
		return nil, errors.New("port " + port + " is not allowed"), true
	}

	// in case IP was provided, net.LookupIP will simply return it
	IPs, err := net.LookupIP(host)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Lookup of %s failed: %v",
			host, err)), false
	}

	// This is net.Dial's default behavior: if the host resolves to multiple IP addresses,
	// Dial will try each IP address in order until one succeeds
	for _, ip := range IPs {
		if !fp.hostIsAllowed(host, ip) {
			continue
		}

		conn, err = fp.dial("tcp", hostPort)
		if err == nil {
			return conn, err, false
		}
	}
	return nil, errors.New("No allowed IP addresses for " + host), true
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
			w.Header().Set("Proxy-Authenticate", "Basic")
			return http.StatusProxyAuthRequired, authErr
		}
	}

	if r.ProtoMajor != 1 && r.ProtoMajor != 2 {
		return http.StatusHTTPVersionNotSupported, errors.New("Unsupported HTTP major version: " + strconv.Itoa(r.ProtoMajor))
	}

	targetConn, err, forbidden := fp.dialRequestedAddress(r)
	if forbidden {
		return http.StatusForbidden, err
	}
	if err != nil {
		// failed, but not because it's forbidden
		return http.StatusBadGateway, errors.New(fmt.Sprintf("dial %s failed: %v", r.URL.Host, err))
	}
	if targetConn == nil {
		// safest to check both error and targetConn afterwards, in case fp.dial (potentially unstable
		// from x/net/proxy) misbehaves and returns both nil or both non-nil
		return http.StatusForbidden, errors.New("hostname " + r.URL.Hostname() + " is not allowed")
	}
	defer targetConn.Close()

	if r.Method == http.MethodConnect {
		if r.ProtoMajor == 2 {
			if len(r.URL.Scheme) > 0 || len(r.URL.Path) > 0 {
				return http.StatusBadRequest, errors.New("CONNECT request has :scheme or/and :path pseudo-header fields")
			}
		}

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
			return 0, dualStream(targetConn, r.Body, w, targetConn)
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
		r.RequestURI = ""

		removeHopByHop(r.Header)

		if !fp.hideIP {
			r.Header.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
		}

		// https://tools.ietf.org/html/rfc7230#section-5.7.1
		if !fp.hideVia {
			r.Header.Add("Via", strconv.Itoa(r.ProtoMajor)+"."+strconv.Itoa(r.ProtoMinor)+" caddy")
		}

		if fp.responseTimeout != nil {
			targetConn.SetDeadline(time.Now().Add(*fp.responseTimeout))
		}

		var response *http.Response
		err = r.Write(targetConn)
		if err != nil {
			return http.StatusBadGateway, errors.New("failed to write http request: " + err.Error())
		}
		response, err = http.ReadResponse(bufio.NewReader(targetConn), r)
		if err != nil {
			return http.StatusBadGateway, errors.New("failed to read http response: " + err.Error())
		}

		// TODO?: check 301 and 302 redirects against ACL and follow them
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
	response.Body.Close()
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
