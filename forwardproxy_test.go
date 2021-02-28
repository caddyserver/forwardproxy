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
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/forwardproxy/httpclient"
	"golang.org/x/net/http2"
)

func dial(proxyAddr, httpProxyVer string, useTLS bool) (net.Conn, error) {
	// always dial localhost for testing purposes
	if useTLS {
		return tls.Dial("tcp", proxyAddr, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{httpVersionToALPN[httpProxyVer]},
		})
	}
	return net.Dial("tcp", proxyAddr)
}

func getViaProxy(targetHost, resource, proxyAddr, httpProxyVer, proxyCredentials string, useTLS bool) (*http.Response, error) {
	proxyConn, err := dial(proxyAddr, httpProxyVer, useTLS)
	if err != nil {
		return nil, err
	}
	return getResourceViaProxyConn(proxyConn, targetHost, resource, httpProxyVer, proxyCredentials)
}

// if connect is not successful - that response is returned, otherwise the requested resource
func connectAndGetViaProxy(targetHost, resource, proxyAddr, httpTargetVer, proxyCredentials, httpProxyVer string, useTLS bool) (*http.Response, error) {
	proxyConn, err := dial(proxyAddr, httpProxyVer, useTLS)
	if err != nil {
		return nil, err
	}

	req := &http.Request{Header: make(http.Header)}
	if len(proxyCredentials) > 0 {
		req.Header.Set("Proxy-Authorization", proxyCredentials)
	}
	req.Host = targetHost
	req.URL, err = url.Parse("https://" + req.Host + "/") // TODO: appending "/" causes file server to NOT issue redirect...
	if err != nil {
		return nil, err
	}
	req.RequestURI = req.Host
	req.Method = "CONNECT"
	req.Proto = httpProxyVer

	var resp *http.Response
	switch httpProxyVer {
	case "HTTP/2.0":
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		pr, pw := io.Pipe()
		req.Body = ioutil.NopCloser(pr)
		t := http2.Transport{}
		clientConn, err := t.NewClientConn(proxyConn)
		if err != nil {
			return nil, err
		}
		resp, err = clientConn.RoundTrip(req)
		if err != nil {
			return resp, err
		}
		proxyConn = httpclient.NewHttp2Conn(proxyConn, pw, resp.Body)
	case "HTTP/1.1":
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		req.Write(proxyConn)
		resp, err = http.ReadResponse(bufio.NewReader(proxyConn), req)
		if err != nil {
			return resp, err
		}
	default:
		panic("proxy ver: " + httpProxyVer)
	}

	if err != nil {
		return resp, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp, err
	}

	return getResourceViaProxyConn(proxyConn, targetHost, resource, httpTargetVer, proxyCredentials)
}

func getResourceViaProxyConn(proxyConn net.Conn, targetHost, resource, httpTargetVer, proxyCredentials string) (*http.Response, error) {
	var err error

	req := &http.Request{Header: make(http.Header)}
	if len(proxyCredentials) > 0 {
		req.Header.Set("Proxy-Authorization", proxyCredentials)
	}
	req.Host = targetHost
	req.URL, err = url.Parse("http://" + targetHost + resource)
	if err != nil {
		return nil, err
	}
	req.RequestURI = req.Host + resource
	req.Method = "GET"
	req.Proto = httpTargetVer

	switch httpTargetVer {
	case "HTTP/2.0":
		req.ProtoMajor = 2
		req.ProtoMinor = 0
		t := http2.Transport{AllowHTTP: true}
		clientConn, err := t.NewClientConn(proxyConn)
		if err != nil {
			return nil, err
		}
		return clientConn.RoundTrip(req)
	case "HTTP/1.1":
		req.ProtoMajor = 1
		req.ProtoMinor = 1
		t := http.Transport{Dial: func(network, addr string) (net.Conn, error) {
			return proxyConn, nil
		}}
		return t.RoundTrip(req)
	default:
		panic("proxy ver: " + httpTargetVer)
	}
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
			return fmt.Errorf("nTotal == responseLen, but haven't seen io.EOF. Expected response: %s\nGot: %s",
				expectedResponse, response)
		}
	}
	response = response[:nTotal]
	if len(expectedResponse) != len(response) {
		return fmt.Errorf("expected length: %d. Got thus far: %d. Expected response: %s\nGot: %s",
			len(expectedResponse), len(response), expectedResponse, response)
	}
	for i := range response {
		if response[i] != expectedResponse[i] {
			return fmt.Errorf("response mismatch at character #%d. Expected response: %s\nGot: %s",
				i, expectedResponse, response)
		}
	}
	return nil
}

func TestPassthrough(t *testing.T) {
	client := &http.Client{Transport: testTransport, Timeout: 2 * time.Second}
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
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyHTTPTestTarget.addr, resource, caddyForwardProxy.addr, httpProxyVer, credentialsEmpty, useTLS)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyHTTPTestTarget.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestGETAuthCorrect(t *testing.T) {
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyHTTPTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpProxyVer, credentialsCorrect, useTLS)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyHTTPTestTarget.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestGETAuthWrong(t *testing.T) {
	const useTLS = true
	for _, wrongCreds := range credentialsWrong {
		for _, httpProxyVer := range testHTTPProxyVersions {
			for _, resource := range testResources {
				response, err := getViaProxy(caddyHTTPTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpProxyVer, wrongCreds, useTLS)
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
	const useTLS = true
	// GETNoAuth to self
	for _, httpTargetVer := range testHTTPTargetVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyForwardProxy.addr, resource, caddyForwardProxy.addr, httpTargetVer, credentialsEmpty, useTLS)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyForwardProxy.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}

	// GETAuthCorrect to self
	for _, httpTargetVer := range testHTTPTargetVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyForwardProxyAuth.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, credentialsCorrect, useTLS)
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
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, httpTargetVer := range testHTTPTargetVersions {
			for _, resource := range testResources {
				response, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyForwardProxy.addr, httpTargetVer, credentialsEmpty, httpProxyVer, useTLS)
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
	const useTLS = true
	for _, httpProxyVer := range testHTTPProxyVersions {
		for _, httpTargetVer := range testHTTPTargetVersions {
			for _, resource := range testResources {
				response, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, credentialsCorrect, httpProxyVer, useTLS)
				if err != nil {
					t.Fatal(httpProxyVer, httpTargetVer, err)
				} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
					t.Fatal(httpProxyVer, httpTargetVer, err)
				}
			}
		}
	}
}

func TestConnectAuthWrong(t *testing.T) {
	const useTLS = true
	for _, wrongCreds := range credentialsWrong {
		for _, httpProxyVer := range testHTTPProxyVersions {
			for _, httpTargetVer := range testHTTPTargetVersions {
				for _, resource := range testResources {
					response, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, wrongCreds, httpProxyVer, useTLS)
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != http.StatusProxyAuthRequired {
						t.Fatalf("Expected response: 407 StatusProxyAuthRequired, Got: %d %s (wrongCreds=%s httpProxyVer=%s httpTargetVer=%s resource=%s)",
							response.StatusCode, response.Status, wrongCreds, httpProxyVer, httpTargetVer, resource)
					}
				}
			}
		}
	}
}

func TestPAC(t *testing.T) {
	client := &http.Client{Transport: testTransport, Timeout: 2 * time.Second}
	resp, err := client.Get("https://" + caddyForwardProxy.addr + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	if err = responseExpected(resp, []byte(fmt.Sprintf(pacFile, caddyForwardProxy.addr))); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("https://" + caddyForwardProxyProbeResist.addr + "/superhiddenfile.pac")
	if err != nil {
		t.Fatal(err)
	}
	if err = responseExpected(resp, []byte(fmt.Sprintf(pacFile, caddyForwardProxyProbeResist.addr))); err != nil {
		t.Fatal(err)
	}
}

func TestCONNECTViaUpstream(t *testing.T) {
	const useTLS = true
	for range make([]byte, 5) { // do several times to test http2 connection reuse
		for _, httpProxyVer := range testHTTPProxyVersions {
			for _, httpTargetVer := range testHTTPTargetVersions {
				for _, resource := range testResources {
					response, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyAuthedUpstreamEnter.addr,
						httpTargetVer, credentialsUpstreamCorrect, httpProxyVer, useTLS)
					if err != nil {
						t.Fatal(err)
					} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}

func TestGETViaUpstream(t *testing.T) {
	const useTLS = true
	for range make([]byte, 5) { // do several times to test http2 connection reuse
		for _, httpProxyVer := range testHTTPProxyVersions {
			for _, resource := range testResources {
				response, err := getViaProxy(caddyHTTPTestTarget.addr, resource, caddyAuthedUpstreamEnter.addr, httpProxyVer,
					credentialsUpstreamCorrect, useTLS)
				if err != nil {
					t.Fatal(err)
				} else if err = responseExpected(response, caddyHTTPTestTarget.contents[resource]); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestUpstreamPassthrough(t *testing.T) {
	// Usptreaming proxy still hosts things as expected
	client := &http.Client{Transport: testTransport, Timeout: 2 * time.Second}
	resp, err := client.Get("https://" + caddyAuthedUpstreamEnter.addr)
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyAuthedUpstreamEnter.contents[""]); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("https://" + caddyAuthedUpstreamEnter.addr + "/pic.png")
	if err != nil {
		t.Fatal(err)
	} else if err = responseExpected(resp, caddyAuthedUpstreamEnter.contents["/pic.png"]); err != nil {
		t.Fatal(err)
	}

	resp, err = client.Get("https://" + caddyAuthedUpstreamEnter.addr + "/idontexist")
	if err != nil {
		t.Fatal(err)
	} else if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected: 404 StatusNotFound, got %d. Response: %#v\n", resp.StatusCode, resp)
	}
}
