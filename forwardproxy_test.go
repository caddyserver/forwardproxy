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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	_ "github.com/mholt/caddy/caddyhttp/header"
	_ "github.com/mholt/caddy/caddyhttp/httpserver"
	_ "github.com/mholt/caddy/caddyhttp/redirect"
	_ "github.com/mholt/caddy/caddyhttp/root"
)

func dial(proxyAddr string, useTls bool) (net.Conn, error) {
	if useTls {
		return tls.Dial("tcp", proxyAddr, &tls.Config{InsecureSkipVerify: true})
	} else {
		return net.Dial("tcp", proxyAddr)
	}
}

func getViaProxy(targetHost, resource, proxyAddr, httpTargetVer, proxyCredentials string, useTls bool) (*http.Response, error) {
	proxyConn, err := dial(proxyAddr, useTls)
	if err != nil {
		return nil, err
	}
	return getResourceViaProxyConn(proxyConn, targetHost, resource, httpTargetVer, proxyCredentials)
}

// if connect is not successful - that response is returned, otherwise the requested resource
func connectAndGetViaProxy(targetHost, resource, proxyAddr, httpTargetVer, proxyCredentials, httpProxyVer string, useTls bool) (*http.Response, error) {
	proxyConn, err := dial(proxyAddr, useTls)
	if err != nil {
		return nil, err
	}

	connectRequest := http.Request{Header: make(http.Header)}
	if len(proxyCredentials) > 0 {
		connectRequest.Header.Set("Proxy-Authorization", proxyCredentials)
	}
	connectRequest.Host = targetHost
	connectRequest.URL, err = url.Parse("http://" + connectRequest.Host)
	if err != nil {
		return nil, err
	}
	connectRequest.RequestURI = connectRequest.Host
	connectRequest.Method = "CONNECT"

	switch httpProxyVer {
	case "HTTP/2.0":
		connectRequest.ProtoMajor = 2
		connectRequest.ProtoMinor = 0
	case "HTTP/1.1":
		connectRequest.ProtoMajor = 1
		connectRequest.ProtoMinor = 1
	default:
		panic("http2ProxyVer: " + httpProxyVer)
	}
	connectRequest.Proto = httpProxyVer

	if len(proxyCredentials) > 0 {
		connectRequest.Header.Set("Proxy-Authorization", proxyCredentials)
	}
	err = connectRequest.Write(proxyConn)
	if err != nil {
		return nil, err
	}
	connectResponse, err := http.ReadResponse(bufio.NewReader(proxyConn), &connectRequest)
	if err != nil {
		return connectResponse, err
	}
	if connectResponse.StatusCode != http.StatusOK {
		return connectResponse, err
	}

	return getResourceViaProxyConn(proxyConn, targetHost, resource, httpTargetVer, proxyCredentials)
}

func getResourceViaProxyConn(proxyConn net.Conn, targetHost, resource, httpTargetVer, proxyCredentials string) (*http.Response, error) {
	var err error

	request := http.Request{Header: make(http.Header)}
	if len(proxyCredentials) > 0 {
		request.Header.Set("Proxy-Authorization", proxyCredentials)
	}
	request.Host = targetHost
	request.URL, err = url.Parse("http://" + request.Host + resource)
	if err != nil {
		return nil, err
	}
	request.RequestURI = request.Host + resource
	request.Method = "GET"

	switch httpTargetVer {
	case "HTTP/2.0":
		request.ProtoMajor = 2
		request.ProtoMinor = 0
	case "HTTP/1.1":
		request.ProtoMajor = 1
		request.ProtoMinor = 1
	default:
		panic("http2TargetVer: " + httpTargetVer)
	}
	request.Proto = httpTargetVer

	err = request.WriteProxy(proxyConn)
	if err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(proxyConn), &request)
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

func TestPassthrough(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: 2 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := client.Get("https://" + caddyForwardProxy.addr)
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyForwardProxy.contents[""]); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("https://" + caddyForwardProxy.addr + "/pic.png")
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyForwardProxy.contents["/pic.png"]); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("https://" + caddyForwardProxy.addr + "/idontexist")
	if err != nil {
		t.Fatal(err)
	} else if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected: 404 StatusNotFound, got %d. Response: %#v\n", resp.StatusCode, resp)
	}
}

func TestGETNoAuth(t *testing.T) {
	useTls := true
	for _, httpTargetVer := range testHTTPVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyTestTarget.addr, resource, caddyForwardProxy.addr, httpTargetVer, credentialsEmpty, useTls)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestGETAuthCorrect(t *testing.T) {
	useTls := true
	for _, httpTargetVer := range testHTTPVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, credentialsCorrect, useTls)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestGETAuthWrong(t *testing.T) {
	useTls := true
	for _, wrongCreds := range credentialsWrong {
		for _, httpTargetVer := range testHTTPVersions {
			for _, resource := range testResources {
				response, err := getViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, wrongCreds, useTls)
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusProxyAuthRequired {
					t.Fatalf("Expected response: 407 StatusProxyAuthRequired, Got: %d %s\n",
						response.StatusCode, response.Status)
				}
			}
		}
	}
}

func TestProxySelfGet(t *testing.T) {
	useTls := true
	// GETNoAuth to self
	for _, httpTargetVer := range testHTTPVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyForwardProxy.addr, resource, caddyForwardProxy.addr, httpTargetVer, credentialsEmpty, useTls)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyForwardProxy.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}

	// GETAuthCorrect to self
	for _, httpTargetVer := range testHTTPVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyForwardProxyAuth.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, credentialsCorrect, useTls)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyForwardProxyAuth.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// TODO: self TestProxySelfConnect.
// It requires tls-in-tls, which tests are not currently set up for.
// Low priority since this is a functionality issue, not security, and it would be easily caught in the wild.

func TestConnectNoAuth(t *testing.T) {
	useTls := true
	for _, httpProxyVer := range testHTTPVersions {
		for _, httpTargetVer := range testHTTPVersions {
			for _, resource := range testResources {
				response, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyForwardProxy.addr, httpTargetVer, credentialsEmpty, httpProxyVer, useTls)
				if err != nil {
					t.Fatal(err)
				} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestConnectAuthCorrect(t *testing.T) {
	useTls := true
	for _, httpProxyVer := range testHTTPVersions {
		for _, httpTargetVer := range testHTTPVersions {
			for _, resource := range testResources {
				response, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, credentialsCorrect, httpProxyVer, useTls)
				if err != nil {
					t.Fatal(err)
				} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestConnectAuthWrong(t *testing.T) {
	useTls := true
	for _, wrongCreds := range credentialsWrong {
		for _, httpProxyVer := range testHTTPVersions {
			for _, httpTargetVer := range testHTTPVersions {
				for _, resource := range testResources {
					response, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, wrongCreds, httpProxyVer, useTls)
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != http.StatusProxyAuthRequired {
						t.Fatalf("Expected response: 407 StatusProxyAuthRequired, Got: %d %s\n",
							response.StatusCode, response.Status)
					}
				}
			}
		}
	}
}

func TestPAC(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: 2 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := client.Get("https://" + caddyForwardProxy.addr + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	splitAddr := strings.Split(caddyForwardProxy.addr, ":")
	if err = responseExpected(resp, []byte(fmt.Sprintf(pacFile, splitAddr[0], splitAddr[1]))); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("https://" + caddyForwardProxyProbeResist.addr + "/superhiddenfile.pac")
	if err != nil {
		t.Fatal(err)
	}
	splitAddr = strings.Split(caddyForwardProxyProbeResist.addr, ":")
	if err = responseExpected(resp, []byte(fmt.Sprintf(pacFile, splitAddr[0], splitAddr[1]))); err != nil {
		t.Fatal(err)
	}
}
