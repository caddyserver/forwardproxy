package forwardproxy

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/mholt/caddy"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"testing"
	"time"
)

var credentialsEmpty = ""
var credentialsCorrect = "Basic dGVzdDpwYXNz" // test:pass
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
var testResources = []string{"", "/pic.png"}
var testHttpVersions = []string{"HTTP/2.0", "HTTP/1.1"}

type caddyTestServer struct {
	*caddy.Instance
	addr string // could be http or https

	HTTPRedirectPort string // used in probe-resist tests to simulate default Caddy's http->https redirect
	root             string // expected to have index.html and pic.png
	directives       []string
	proxyEnabled     bool
	proxyDirectives  []string
	contents         map[string][]byte
}

var (
	caddyForwardProxy            caddyTestServer
	caddyForwardProxyAuth        caddyTestServer // requires auth
	caddyForwardProxyProbeResist caddyTestServer // requires auth, and has probing resistance on
	caddyDummyProbeResist        caddyTestServer // same as caddyForwardProxyProbeResist, but w/o forwardproxy
	caddyTestTarget              caddyTestServer
)

func (c *caddyTestServer) marshal() []byte {
	mainBlock := []string{c.addr + " {",
		"root " + c.root}
	mainBlock = append(mainBlock, c.directives...)
	if c.proxyEnabled {
		if len(c.proxyDirectives) == 0 {
			mainBlock = append(mainBlock, "forwardproxy")
		} else {
			forwardProxyBlock := []string{"forwardproxy {"}
			forwardProxyBlock = append(forwardProxyBlock, strings.Join(c.proxyDirectives, "\n"))
			forwardProxyBlock = append(forwardProxyBlock, "}")
			mainBlock = append(mainBlock, strings.Join(forwardProxyBlock, "\n"))
		}
	}
	mainBlock = append(mainBlock, "}")
	if len(c.HTTPRedirectPort) > 0 {
		// TODO: this is not good enough, since `func redirPlaintextHost(cfg *SiteConfig) *SiteConfig`
		// https://github.com/mholt/caddy/blob/master/caddyhttp/httpserver/https.go#L142 can change in future
		// and we won't know.
		redirectBlock := []string{"http://*:" + c.HTTPRedirectPort + " {",
			"redir https://" + c.addr + "{uri}",
			"header / Connection close",
			"}"}
		mainBlock = append(mainBlock, redirectBlock...)
	}
	// fmt.Println(strings.Join(mainBlock, "\n"))
	return []byte(strings.Join(mainBlock, "\n"))
}

func (c *caddyTestServer) StartTestServer() {
	var err error
	c.Instance, err = caddy.Start(caddy.CaddyfileInput{Contents: c.marshal(), ServerTypeName: "http"})
	if err != nil {
		panic(err)
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
}

func TestMain(m *testing.M) {
	caddyForwardProxy = caddyTestServer{addr: "127.0.0.1:1984", root: "./test/forwardproxy",
		directives:   []string{"tls self_signed"},
		proxyEnabled: true, proxyDirectives: []string{"serve_pac"}}
	caddyForwardProxy.StartTestServer()

	caddyForwardProxyAuth = caddyTestServer{addr: "127.0.0.1:4891", root: "./test/forwardproxy",
		directives:   []string{"tls self_signed"},
		proxyEnabled: true, proxyDirectives: []string{"basicauth test pass"}}
	caddyForwardProxyAuth.StartTestServer()

	caddyForwardProxyProbeResist = caddyTestServer{addr: "127.0.0.1:8888", root: "./test/forwardproxy",
		directives: []string{"tls self_signed"}, HTTPRedirectPort: "8880",
		proxyEnabled: true, proxyDirectives: []string{"basicauth test pass",
			"probe_resistance test.localhost",
			"serve_pac superhiddenfile.pac"}}
	caddyForwardProxyProbeResist.StartTestServer()

	caddyDummyProbeResist = caddyTestServer{addr: "127.0.0.1:9999", root: "./test/forwardproxy",
		directives: []string{"tls self_signed"}, HTTPRedirectPort: "9980",
		proxyEnabled: false}
	caddyDummyProbeResist.StartTestServer()

	// 127.0.0.1 and localhost are both used to avoid Caddy matching and routing proxy requests internally
	caddyTestTarget = caddyTestServer{addr: "localhost:6451", root: "./test/index",
		directives:   []string{},
		proxyEnabled: false}
	caddyTestTarget.StartTestServer()

	retCode := m.Run()

	caddyForwardProxy.Stop()
	caddyForwardProxyAuth.Stop()
	caddyForwardProxyProbeResist.Stop()
	caddyDummyProbeResist.Stop()
	caddyTestTarget.Stop()

	os.Exit(retCode)
}

// This is a sanity check confirming that target servers actually directly serve what they are expected to.
// (And that they don't serve what they should not)
func TestTheTest(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: 2 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}

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

func TestIsSubdomain(t *testing.T) {
	testSubDomain := func(s, domain string, expectedResult bool) {
		result := isSubdomain(s, domain)
		if result != expectedResult {
			t.Fatalf("Expected: isSubdomain(%s, %s) is %v, Got: %v", s, domain, expectedResult, result)
		}
	}
	testSubDomain("hoooli.abc", "hooya.ya", false)
	testSubDomain("", "hooya.ya", false)
	testSubDomain("hoooli.abc", "", false)
	testSubDomain("hoooli.abc", "hiddenlink.localhost", false)
	testSubDomain("www.hoooli.abc", "hoooli.abc", true)
	testSubDomain("hoooli.abc", "hoooli.abc", true)
	testSubDomain(".hoooli.abc", "hoooli.abc", true)
	testSubDomain("sup.hoooli.abc", "hoooli.abc", true)
	testSubDomain("qwe.qwe.qwe.hoooli.abc", "hoooli.abc", true)
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
		b, err := httputil.DumpRequest(v, false)
		if err != nil {
			return err.Error()
		} else {
			return string(b)
		}
	case *http.Response:
		if v == nil {
			return "httpdump: nil"
		}
		b, err := httputil.DumpResponse(v, false)
		if err != nil {
			return err.Error()
		} else {
			return string(b)
		}
	default:
		return "httpdump: wrong type"
	}
}
