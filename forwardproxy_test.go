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
	"testing"
	"bytes"
	"github.com/mholt/caddy"
	_ "github.com/mholt/caddy/caddyhttp/httpserver"
	_ "github.com/mholt/caddy/caddyhttp/root"
	"net/http"
	"time"
	"fmt"
	"os"
	"crypto/tls"
	"io/ioutil"
	"io"
	"errors"
	"net/url"
)
// TODO: force http1 and http2
func TestIsSubdomain(t *testing.T) {
	testSubDomain := func(s, domain string, expectedResult bool) {
		result := isSubdomain(s, domain)
		if result != expectedResult {
			t.Fatalf("Expected: isSubdomain(%s, %s) is %b, Got: %b", s, domain, expectedResult, result)
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

type caddyTestServer struct {
	*caddy.Instance
	addr           string
	root           string // expected to have index.html and pic.png
	directives     []string
	indexContents  []byte
	picPngContents []byte
}

var (
	caddyForwardProxy caddyTestServer
	caddyTLSTestTarget caddyTestServer
	caddyTestTarget caddyTestServer
)

func (c *caddyTestServer) marshal() []byte {
	b := bytes.Buffer{}
	_, err := b.WriteString(c.addr + "\n\n")
	if err != nil {
		panic(err)
	}
	_, err = b.WriteString("root " + c.root +"\n")
	if err != nil {
		panic(err)
	}
	for _, h := range c.directives {
		b.WriteString(h + "\n")
		if err != nil {
			panic(err)
		}
	}
	return b.Bytes()
}

func  (c *caddyTestServer) StartTestServer() {
	var err error
	c.Instance, err = caddy.Start(caddy.CaddyfileInput{Contents: c.marshal(), ServerTypeName: "http"})
	if err != nil {
		panic(err)
	}
	c.indexContents, err = ioutil.ReadFile(c.root + "/index.html")
	if err != nil {
		panic(err)
	}
	c.picPngContents, err = ioutil.ReadFile(c.root + "/pic.png")
	if err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	caddyForwardProxy = caddyTestServer{addr: "localhost:1984", root: "./test/forwardproxy",
		directives: []string{"tls self_signed", "forwardproxy"}}
	caddyForwardProxy.StartTestServer()
	caddyTLSTestTarget = caddyTestServer{addr: "localhost:6451", root: "./test/index",
		directives: []string{"tls self_signed"}}
	caddyTLSTestTarget.StartTestServer()
	caddyTestTarget = caddyTestServer{addr: "localhost:4516", root: "./test/index"}
	caddyTestTarget.StartTestServer()

	retCode := m.Run()

	caddyForwardProxy.Stop()
	caddyTLSTestTarget.Stop()
	caddyTestTarget.Stop()

	os.Exit(retCode)
}

// If response is expected: returns nil.
func responseExpected(res *http.Response, expectedResponse []byte) error {
	responseLen := len(expectedResponse) + 2 // 2 extra bytes is enough to detected that expectedResponse is longer
	response := make([]byte, responseLen)
	var nTotal int
	for {
		n, err := res.Body.Read(response[nTotal:])
		nTotal += n
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		if nTotal == responseLen {
			return errors.New(fmt.Sprintf("nTotal == responseLen, but haven't seen io.EOF. Expected response: %s\nGot: %s\n",
				expectedResponse, response))
		}
	}
	response = response[:nTotal]
	if len(expectedResponse) != len(response) {
		return errors.New(fmt.Sprintf("Expected length: %d. Got thus far: %d. Expected response: %s\nGot: %s\n",
			len(expectedResponse), len(response), expectedResponse, response))
	}
	for i := range response {
		if response[i] != expectedResponse[i] {
			return errors.New(fmt.Sprintf("Response mismatch at character #%d. Expected response: %s\nGot: %s\n",
				i, expectedResponse, response))
		}
	}
	return nil
}

// This is a sanity check confirming that target servers actually directly serve what they are expected to.
// (And that they don't serve what they should not)
func TestTheTest(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: 2 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}

	// Request index
	resp, err := client.Get("https://" + caddyTLSTestTarget.addr)
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTLSTestTarget.indexContents); err != nil {
		t.Fatal(err)
	}

	// Request pic
	resp, err = client.Get("https://" + caddyTLSTestTarget.addr + "/pic.png")
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTLSTestTarget.picPngContents); err != nil {
		t.Fatal(err)
	}

	// Request pic, but expect index. Should fail
	resp, err = client.Get("https://" + caddyTLSTestTarget.addr + "/pic.png")
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTLSTestTarget.indexContents); err == nil {
		t.Fatal(err)
	}

	// Request index, but expect pic. Should fail
	resp, err = client.Get("https://" + caddyTLSTestTarget.addr)
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTLSTestTarget.picPngContents); err == nil {
		t.Fatal(err)
	}

	// Request non-existing resource
	resp, err = client.Get("https://" + caddyTLSTestTarget.addr + "/idontexist")
	if err != nil {
		t.Fatal(err)
	} else if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected: 404 StatusNotFound, got %s. Response: %#v\n", resp.StatusCode, resp)
	}

	// All again for non-TLS
	resp, err = client.Get("http://" + caddyTestTarget.addr)
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTestTarget.indexContents); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("http://" + caddyTestTarget.addr + "/pic.png")
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTestTarget.picPngContents); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("http://" + caddyTestTarget.addr + "/pic.png")
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTestTarget.indexContents); err == nil {
		t.Fatal(err)
	}

	resp, err = client.Get("http://" + caddyTestTarget.addr)
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyTestTarget.picPngContents); err == nil {
		t.Fatal(err)
	}

	resp, err = client.Get("http://" + caddyTestTarget.addr + "/idontexist")
	if err != nil {
		t.Fatal(err)
	} else if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected: 404 StatusNotFound, got %s. Response: %#v\n", resp.StatusCode, resp)
	}
}

func TestPassthrough(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: 2 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := client.Get("https://" + caddyForwardProxy.addr)
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyForwardProxy.indexContents); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("https://" + caddyForwardProxy.addr + "/pic.png")
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyForwardProxy.picPngContents); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("https://" + caddyForwardProxy.addr + "/idontexist")
	if err != nil {
		t.Fatal(err)
	} else if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected: 404 StatusNotFound, got %s. Response: %#v\n", resp.StatusCode, resp)
	}
}