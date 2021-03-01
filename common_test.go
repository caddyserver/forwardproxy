package forwardproxy

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

var credentialsEmpty = ""
var credentialsCorrectPlain = "test:pass"
var credentialsCorrect = "Basic dGVzdDpwYXNz"                                 // test:pass
var credentialsUpstreamCorrect = "basic dXBzdHJlYW10ZXN0OnVwc3RyZWFtcGFzcw==" // upstreamtest:upstreampass
var credentialsWrong = []string{
	"",
	"\"\"",
	"Basic dzp3",
	"Basic \"\"",
	"Foo bar",
	"Tssssssss",
	"Basic dpz3 asp",
}

/*
Test naming: Test{httpVer}Proxy{Method}{Auth}{Credentials}{httpVer}
GET/CONNECT -- get gets, connect connects and gets
Auth/NoAuth
Empty/Correct/Wrong -- tries different credentials
*/
var testResources = []string{"/", "/pic.png"}
var testHTTPProxyVersions = []string{"HTTP/2.0", "HTTP/1.1"}
var testHTTPTargetVersions = []string{"HTTP/1.1"}
var httpVersionToALPN = map[string]string{
	"HTTP/1.1": "http/1.1",
	"HTTP/2.0": "h2",
}

var blacklistedDomain = "google-public-dns-a.google.com" // supposed to ever resolve to one of 2 IP addresses below
var blacklistedIPv4 = "8.8.8.8"
var blacklistedIPv6 = "2001:4860:4860::8888"

type caddyTestServer struct {
	addr string
	tls  bool

	httpRedirPort string // used in probe-resist tests to simulate default Caddy's http->https redirect

	root         string // expected to have index.html and pic.png
	directives   []string
	proxyHandler *Handler
	contents     map[string][]byte
}

var (
	caddyForwardProxy            caddyTestServer
	caddyForwardProxyAuth        caddyTestServer // requires auth
	caddyHTTPForwardProxyAuth    caddyTestServer // requires auth, does not use TLS
	caddyForwardProxyProbeResist caddyTestServer // requires auth, and has probing resistance on
	caddyDummyProbeResist        caddyTestServer // same as caddyForwardProxyProbeResist, but w/o forwardproxy

	caddyForwardProxyWhiteListing        caddyTestServer
	caddyForwardProxyBlackListing        caddyTestServer
	caddyForwardProxyNoBlacklistOverride caddyTestServer // to test default blacklist

	// authenticated server upstreams to authenticated https proxy with different credentials
	caddyAuthedUpstreamEnter caddyTestServer

	caddyTestTarget     caddyTestServer // whitelisted by caddyForwardProxyWhiteListing
	caddyHTTPTestTarget caddyTestServer // serves plain http on 6480
)

func (c *caddyTestServer) server() *caddyhttp.Server {
	host, port, err := net.SplitHostPort(c.addr)
	if err != nil {
		panic(err)
	}

	handlerJSON := func(h caddyhttp.MiddlewareHandler) json.RawMessage {
		return caddyconfig.JSONModuleObject(h, "handler", h.(caddy.Module).CaddyModule().ID.Name(), nil)
	}

	// create the routes
	var routes caddyhttp.RouteList
	if c.tls {
		// cheap hack for our tests to get TLS certs for the hostnames that
		// it needs TLS certs for: create an empty route with a single host
		// matcher for that hostname, and auto HTTPS will do the rest
		hostMatcherJSON, err := json.Marshal(caddyhttp.MatchHost{host})
		if err != nil {
			panic(err)
		}
		matchersRaw := caddyhttp.RawMatcherSets{
			caddy.ModuleMap{"host": hostMatcherJSON},
		}
		routes = append(routes, caddyhttp.Route{MatcherSetsRaw: matchersRaw})
	}
	if c.proxyHandler != nil {
		if host != "" {
			// tell the proxy which hostname to serve the proxy on; this must
			// be distinct from the host matcher, since the proxy basically
			// does its own host matching
			c.proxyHandler.Hosts = caddyhttp.MatchHost{host}
		}
		routes = append(routes, caddyhttp.Route{
			HandlersRaw: []json.RawMessage{handlerJSON(c.proxyHandler)},
		})
	}
	if c.root != "" {
		routes = append(routes, caddyhttp.Route{
			HandlersRaw: []json.RawMessage{
				handlerJSON(&fileserver.FileServer{Root: c.root}),
			},
		})
	}

	srv := &caddyhttp.Server{
		Listen: []string{":" + port},
		Routes: routes,
	}
	if c.tls {
		srv.TLSConnPolicies = caddytls.ConnectionPolicies{{}}
	} else {
		srv.AutoHTTPS = &caddyhttp.AutoHTTPSConfig{Disabled: true}
	}

	if c.contents == nil {
		c.contents = make(map[string][]byte)
	}
	index, err := ioutil.ReadFile(c.root + "/index.html")
	if err != nil {
		panic(err)
	}
	c.contents[""] = index
	c.contents["/"] = index
	c.contents["/index.html"] = index
	c.contents["/pic.png"], err = ioutil.ReadFile(c.root + "/pic.png")
	if err != nil {
		panic(err)
	}

	return srv
}

// For simulating/mimicing Caddy's built-in auto-HTTPS redirects. Super hacky but w/e.
func (c *caddyTestServer) redirServer() *caddyhttp.Server {
	return &caddyhttp.Server{
		Listen: []string{":" + c.httpRedirPort},
		Routes: caddyhttp.RouteList{
			{
				Handlers: []caddyhttp.MiddlewareHandler{
					caddyhttp.StaticResponse{
						StatusCode: caddyhttp.WeakString(strconv.Itoa(http.StatusPermanentRedirect)),
						Headers: http.Header{
							"Location":   []string{"https://" + c.addr + "/{http.request.uri}"},
							"Connection": []string{"close"},
						},
						Close: true,
					},
				},
			},
		},
	}
}

func TestMain(m *testing.M) {
	caddyForwardProxy = caddyTestServer{
		addr: "127.0.19.84:1984",
		root: "./test/forwardproxy",
		tls:  true,
		proxyHandler: &Handler{
			PACPath: defaultPACPath,
			ACL:     []ACLRule{{Allow: true, Subjects: []string{"all"}}},
		},
	}

	caddyForwardProxyAuth = caddyTestServer{
		addr: "127.0.0.1:4891",
		root: "./test/forwardproxy",
		tls:  true,
		proxyHandler: &Handler{
			PACPath:       defaultPACPath,
			ACL:           []ACLRule{{Subjects: []string{"all"}, Allow: true}},
			BasicauthUser: "test",
			BasicauthPass: "pass",
		},
	}

	caddyHTTPForwardProxyAuth = caddyTestServer{
		addr: "127.0.69.73:6973",
		root: "./test/forwardproxy",
		proxyHandler: &Handler{
			PACPath:       defaultPACPath,
			ACL:           []ACLRule{{Subjects: []string{"all"}, Allow: true}},
			BasicauthUser: "test",
			BasicauthPass: "pass",
		},
	}

	caddyForwardProxyProbeResist = caddyTestServer{
		addr: "127.0.88.88:8888",
		root: "./test/forwardproxy",
		tls:  true,
		proxyHandler: &Handler{
			PACPath:         "/superhiddenfile.pac",
			ACL:             []ACLRule{{Subjects: []string{"all"}, Allow: true}},
			ProbeResistance: &ProbeResistance{Domain: "test.localhost"},
			BasicauthUser:   "test",
			BasicauthPass:   "pass",
		},
		httpRedirPort: "8880",
	}

	caddyDummyProbeResist = caddyTestServer{
		addr:          "127.0.99.99:9999",
		root:          "./test/forwardproxy",
		tls:           true,
		httpRedirPort: "9980",
	}

	caddyTestTarget = caddyTestServer{
		addr: "127.0.64.51:6451",
		root: "./test/index",
	}

	caddyHTTPTestTarget = caddyTestServer{
		addr: "localhost:6480",
		root: "./test/index",
	}

	caddyAuthedUpstreamEnter = caddyTestServer{
		addr: "127.0.65.25:6585",
		root: "./test/upstreamingproxy",
		tls:  true,
		proxyHandler: &Handler{
			Upstream:      "https://test:pass@127.0.0.1:4891",
			BasicauthUser: "upstreamtest",
			BasicauthPass: "upstreampass",
		},
	}

	caddyForwardProxyWhiteListing = caddyTestServer{
		addr: "127.0.87.76:8776",
		root: "./test/forwardproxy",
		tls:  true,
		proxyHandler: &Handler{
			ACL: []ACLRule{
				{Subjects: []string{"127.0.64.51"}, Allow: true},
				{Subjects: []string{"all"}, Allow: false},
			},
			AllowedPorts: []int{6451},
		},
	}

	caddyForwardProxyBlackListing = caddyTestServer{
		addr: "127.0.66.76:6676",
		root: "./test/forwardproxy",
		tls:  true,
		proxyHandler: &Handler{
			ACL: []ACLRule{
				{Subjects: []string{blacklistedIPv4 + "/30"}, Allow: false},
				{Subjects: []string{blacklistedIPv6}, Allow: false},
				{Subjects: []string{"all"}, Allow: true},
			},
		},
	}

	caddyForwardProxyNoBlacklistOverride = caddyTestServer{
		addr:         "127.0.66.76:6679",
		root:         "./test/forwardproxy",
		tls:          true,
		proxyHandler: &Handler{},
	}

	// done configuring all the servers; now build the HTTP app
	httpApp := caddyhttp.App{
		HTTPPort: 1080, // use a high port to avoid permission issues
		Servers: map[string]*caddyhttp.Server{
			"caddyForwardProxy":                    caddyForwardProxy.server(),
			"caddyForwardProxyAuth":                caddyForwardProxyAuth.server(),
			"caddyHTTPForwardProxyAuth":            caddyHTTPForwardProxyAuth.server(),
			"caddyForwardProxyProbeResist":         caddyForwardProxyProbeResist.server(),
			"caddyDummyProbeResist":                caddyDummyProbeResist.server(),
			"caddyTestTarget":                      caddyTestTarget.server(),
			"caddyHTTPTestTarget":                  caddyHTTPTestTarget.server(),
			"caddyAuthedUpstreamEnter":             caddyAuthedUpstreamEnter.server(),
			"caddyForwardProxyWhiteListing":        caddyForwardProxyWhiteListing.server(),
			"caddyForwardProxyBlackListing":        caddyForwardProxyBlackListing.server(),
			"caddyForwardProxyNoBlacklistOverride": caddyForwardProxyNoBlacklistOverride.server(),

			// HTTP->HTTPS redirect simulation servers for those which have a redir port configured
			"caddyForwardProxyProbeResist_redir": caddyForwardProxyProbeResist.redirServer(),
			"caddyDummyProbeResist_redir":        caddyDummyProbeResist.redirServer(),
		},
		GracePeriod: caddy.Duration(1 * time.Second), // keep tests fast
	}
	httpAppJSON, err := json.Marshal(httpApp)
	if err != nil {
		panic(err)
	}

	// ensure we always use internal issuer and not a public CA
	tlsApp := caddytls.TLS{
		Automation: &caddytls.AutomationConfig{
			Policies: []*caddytls.AutomationPolicy{
				{
					IssuersRaw: []json.RawMessage{json.RawMessage(`{"module": "internal"}`)},
				},
			},
		},
	}
	tlsAppJSON, err := json.Marshal(tlsApp)
	if err != nil {
		panic(err)
	}

	// configure the default CA so that we don't try to install trust, just for our tests
	falseBool := false
	pkiApp := caddypki.PKI{
		CAs: map[string]*caddypki.CA{
			"local": {InstallTrust: &falseBool},
		},
	}
	pkiAppJSON, err := json.Marshal(pkiApp)
	if err != nil {
		panic(err)
	}

	// build final config
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{Disabled: true},
		AppsRaw: caddy.ModuleMap{
			"http": httpAppJSON,
			"tls":  tlsAppJSON,
			"pki":  pkiAppJSON,
		},
	}

	// start the engines
	err = caddy.Run(cfg)
	if err != nil {
		panic(err)
	}

	retCode := m.Run()

	caddy.Stop()

	os.Exit(retCode)
}

// This is a sanity check confirming that target servers actually directly serve what they are expected to.
// (And that they don't serve what they should not)
func TestTheTest(t *testing.T) {
	client := &http.Client{Transport: testTransport, Timeout: 2 * time.Second}

	// Request index
	resp, err := client.Get("http://" + caddyTestTarget.addr)
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTestTarget.contents[""]); err != nil {
		t.Fatal(err)
	}

	// Request pic
	resp, err = client.Get("http://" + caddyTestTarget.addr + "/pic.png")
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTestTarget.contents["/pic.png"]); err != nil {
		t.Fatal(err)
	}

	// Request pic, but expect index. Should fail
	resp, err = client.Get("http://" + caddyTestTarget.addr + "/pic.png")
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTestTarget.contents[""]); err == nil {
		t.Fatal(err)
	}

	// Request index, but expect pic. Should fail
	resp, err = client.Get("http://" + caddyTestTarget.addr)
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTestTarget.contents["/pic.png"]); err == nil {
		t.Fatal(err)
	}

	// Request non-existing resource
	resp, err = client.Get("http://" + caddyTestTarget.addr + "/idontexist")
	if err != nil {
		t.Fatal(err)
	} else if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected: 404 StatusNotFound, got %d. Response: %#v\n", resp.StatusCode, resp)
	}
}

func debugIoCopy(dst io.Writer, src io.Reader, prefix string) (written int64, err error) {
	buf := make([]byte, 32*1024)
	flusher, ok := dst.(http.Flusher)
	for {
		nr, er := src.Read(buf)
		fmt.Printf("[%s] Read err %#v\n%s", prefix, er, hex.Dump(buf[0:nr]))
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if ok {
				flusher.Flush()
			}
			fmt.Printf("[%s] Wrote %v %v\n", prefix, nw, ew)
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
	fmt.Printf("[%s] Returning with %#v %#v\n", prefix, written, err)
	return
}

func httpdump(r interface{}) string {
	switch v := r.(type) {
	case *http.Request:
		if v == nil {
			return "httpdump: nil"
		}
		b, err := httputil.DumpRequest(v, true)
		if err != nil {
			return err.Error()
		}
		return string(b)
	case *http.Response:
		if v == nil {
			return "httpdump: nil"
		}
		b, err := httputil.DumpResponse(v, true)
		if err != nil {
			return err.Error()
		}
		return string(b)
	default:
		return "httpdump: wrong type"
	}
}

var testTransport = &http.Transport{
	ResponseHeaderTimeout: 2 * time.Second,
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		// always dial localhost for testing purposes
		return new(net.Dialer).DialContext(ctx, network, addr)
	},
	DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		// always dial localhost for testing purposes
		conn, err := new(net.Dialer).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return tls.Client(conn, &tls.Config{InsecureSkipVerify: true}), nil
	},
}

const defaultPACPath = "/proxy.pac"
