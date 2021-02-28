// tests ./httpclient/ but is in root as it needs access to test files in root
package forwardproxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/forwardproxy/httpclient"
)

func TestHttpClient(t *testing.T) {
	_test := func(urlSchemeAndCreds, urlAddress string) {
		for _, httpProxyVer := range testHTTPProxyVersions {
			for _, httpTargetVer := range testHTTPTargetVersions {
				for _, resource := range testResources {
					// always dial localhost for testing purposes
					proxyURL := fmt.Sprintf("%s@%s", urlSchemeAndCreds, urlAddress)

					dialer, err := httpclient.NewHTTPConnectDialer(proxyURL)
					if err != nil {
						t.Fatal(err)
					}
					dialer.DialTLS = func(network string, address string) (net.Conn, string, error) {
						// always dial localhost for testing purposes
						conn, err := tls.Dial(network, address, &tls.Config{
							InsecureSkipVerify: true,
							NextProtos:         []string{httpVersionToALPN[httpProxyVer]},
						})
						if err != nil {
							return nil, "", err
						}
						return conn, conn.ConnectionState().NegotiatedProtocol, nil
					}

					// always dial localhost for testing purposes
					conn, err := dialer.Dial("tcp", caddyTestTarget.addr)
					if err != nil {
						t.Fatal(err)
					}
					response, err := getResourceViaProxyConn(conn, caddyTestTarget.addr, resource, httpTargetVer, credentialsCorrect)
					if err != nil {
						t.Fatal(httpProxyVer, httpTargetVer, err)
					} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
						t.Fatal(httpProxyVer, httpTargetVer, err)
					}
				}
			}
		}
	}

	_test("https://"+credentialsCorrectPlain, caddyForwardProxyAuth.addr)
	_test("http://"+credentialsCorrectPlain, caddyHTTPForwardProxyAuth.addr)
}

func TestHttpClientH2Multiplexing(t *testing.T) {
	// doesn't actually confirm that it is multiplexed, just that it doesn't break things
	// but it was manually inspected in Wireshark when this code was committed
	httpProxyVer := "HTTP/2.0"
	httpTargetVer := "HTTP/1.1"

	dialer, err := httpclient.NewHTTPConnectDialer("https://" + credentialsCorrectPlain + "@" + caddyForwardProxyAuth.addr)
	if err != nil {
		t.Fatal(err)
	}
	dialer.DialTLS = func(network string, address string) (net.Conn, string, error) {
		// always dial localhost for testing purposes
		conn, err := tls.Dial(network, address, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{httpVersionToALPN[httpProxyVer]},
		})
		if err != nil {
			return nil, "", err
		}
		return conn, conn.ConnectionState().NegotiatedProtocol, nil
	}

	retries := 20
	sleepInterval := time.Millisecond * 100

	var wg sync.WaitGroup
	wg.Add(retries + 1) // + for one serial launch
	_test := func() {
		defer wg.Done()
		for _, resource := range testResources {
			// always dial localhost for testing purposes
			conn, err := dialer.Dial("tcp", caddyTestTarget.addr)
			if err != nil {
				t.Fatal(err)
			}
			response, err := getResourceViaProxyConn(conn, caddyTestTarget.addr, resource, httpTargetVer, credentialsCorrect)
			if err != nil {
				t.Fatal(httpProxyVer, httpTargetVer, err)
			} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
				t.Fatal(httpProxyVer, httpTargetVer, err)
			}
		}
	}

	_test() // do serially at least once

	for i := 0; i < retries; i++ {
		go _test()
		time.Sleep(sleepInterval)
	}
}
