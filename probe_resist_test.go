package forwardproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

func TestGETAuthCorrectProbeResist(t *testing.T) {
	useTls := true
	for _, httpProxyVer := range testHttpProxyVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyProbeResist.addr, httpProxyVer, credentialsCorrect, useTls)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestGETAuthWrongProbeResist(t *testing.T) {
	useTls := true
	for _, wrongCreds := range credentialsWrong {
		for _, httpProxyVer := range testHttpProxyVersions {
			for _, resource := range testResources {
				responseProbeResist, err := getViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyProbeResist.addr, httpProxyVer, wrongCreds, useTls)
				if err != nil {
					t.Fatal(err)
				}
				// get response from reference server without forwardproxy and compare them
				responseReference, err := getViaProxy(caddyTestTarget.addr, resource, caddyDummyProbeResist.addr, httpProxyVer, wrongCreds, useTls)
				if err != nil {
					t.Fatal(err)
				}
				// as a sanity check, get 407 from simple authenticated forwardproxy
				responseForwardProxy, err := getViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpProxyVer, wrongCreds, useTls)
				if err != nil {
					t.Fatal(err)
				}
				if responseProbeResist.StatusCode != responseReference.StatusCode {
					t.Fatalf("Expected response: %d, Got: %d\n",
						responseReference.StatusCode, responseProbeResist.StatusCode)
				}
				if err = responsesAreEqual(responseProbeResist, responseReference); err != nil {
					t.Fatal(err)
				}
				if err = responsesAreEqual(responseProbeResist, responseForwardProxy); err == nil {
					t.Fatal("Responses from servers with and without forwardproxy are expected to be different.")
				}
			}
			for _, resource := range testResources {
				responseProbeResist, err := getViaProxy(caddyForwardProxyProbeResist.addr, resource, caddyForwardProxyProbeResist.addr, httpProxyVer, wrongCreds, useTls)
				if err != nil {
					t.Fatal(err)
				}
				// get response from reference server without forwardproxy and compare them
				responseReference, err := getViaProxy(caddyDummyProbeResist.addr, resource, caddyDummyProbeResist.addr, httpProxyVer, wrongCreds, useTls)
				if err != nil {
					t.Fatal(err)
				}
				// as a sanity check, get 407 from simple authenticated forwardproxy
				responseForwardProxy, err := getViaProxy(caddyForwardProxyAuth.addr, resource, caddyForwardProxyAuth.addr, httpProxyVer, wrongCreds, useTls)
				if err != nil {
					t.Fatal(err)
				}
				if responseProbeResist.StatusCode != http.StatusOK {
					t.Fatalf("Expected response: 200 StatusOK, Got: %d\n",
						responseProbeResist.StatusCode)
				}
				if err = responsesAreEqual(responseProbeResist, responseReference); err != nil {
					t.Fatal(err)
				}
				if err = responsesAreEqual(responseProbeResist, responseForwardProxy); err == nil {
					t.Fatal("Responses from servers with and without forwardproxy are expected to be different.")
				}
			}
		}
	}
}

// test that responses on http redirect port are same
func TestGETAuthWrongProbeResistRedir(t *testing.T) {
	useTls := false
	httpProxyVer := "HTTP/1.1"
	for _, wrongCreds := range credentialsWrong {
		// request test target
		for _, resource := range testResources {
			responseProbeResist, rPRerr := getViaProxy(caddyTestTarget.addr, resource, stripPort(caddyForwardProxyProbeResist.addr)+":"+caddyForwardProxyProbeResist.HTTPRedirectPort,
				httpProxyVer, wrongCreds, useTls)
			// get response from reference server without forwardproxy and compare them
			responseReference, rRerr := getViaProxy(caddyTestTarget.addr, resource, stripPort(caddyDummyProbeResist.addr)+":"+caddyDummyProbeResist.HTTPRedirectPort,
				httpProxyVer, wrongCreds, useTls)
			if (rPRerr == nil && rRerr != nil) || (rPRerr != nil && rRerr == nil) {
				t.Fatalf("Reference error: %s. Probe resist error: %s", rRerr, rPRerr)
			}
			if responseProbeResist.StatusCode != responseReference.StatusCode {
				t.Fatalf("Expected response: %d, Got: %d\n",
					responseReference.StatusCode, responseProbeResist.StatusCode)
			}
			if err := responsesAreEqual(responseProbeResist, responseReference); err != nil {
				t.Fatal(err)
			}
		}
		// request self
		for _, resource := range testResources {
			responseProbeResist, err := getViaProxy(caddyForwardProxyProbeResist.addr, resource, stripPort(caddyForwardProxyProbeResist.addr)+":"+caddyForwardProxyProbeResist.HTTPRedirectPort,
				httpProxyVer, wrongCreds, useTls)
			if err != nil {
				t.Fatal(err)
			}
			// get response from reference server without forwardproxy and compare them
			responseReference, err := getViaProxy(caddyDummyProbeResist.addr, resource, stripPort(caddyDummyProbeResist.addr)+":"+caddyDummyProbeResist.HTTPRedirectPort,
				httpProxyVer, wrongCreds, useTls)
			if err != nil {
				t.Fatal(err)
			}
			if responseProbeResist.StatusCode != responseReference.StatusCode {
				t.Fatalf("Expected response: %d, Got: %d\n",
					responseReference.StatusCode, responseProbeResist.StatusCode)
			}
			if err = responsesAreEqual(responseProbeResist, responseReference); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestConnectAuthCorrectProbeResist(t *testing.T) {
	useTls := true
	for _, httpProxyVer := range testHttpProxyVersions {
		for _, httpTargetVer := range testHttpTargetVersions {
			for _, resource := range testResources {
				response, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyProbeResist.addr, httpTargetVer, credentialsCorrect, httpProxyVer, useTls)
				if err != nil {
					t.Fatal(err)
				} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

func TestConnectAuthWrongProbeResist(t *testing.T) {
	useTls := true
	for _, wrongCreds := range credentialsWrong {
		for _, httpProxyVer := range testHttpProxyVersions {
			for _, httpTargetVer := range testHttpTargetVersions {
				for _, resource := range testResources {
					responseProbeResist, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyProbeResist.addr, httpTargetVer, wrongCreds, httpProxyVer, useTls)
					if err != nil {
						t.Fatal(err)
					}
					// get response from reference server without forwardproxy and compare them
					responseReference, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyDummyProbeResist.addr, httpTargetVer, wrongCreds, httpProxyVer, useTls)
					if err != nil {
						t.Fatal(err)
					}
					// as a sanity check, get 407 from simple authenticated forwardproxy
					responseForwardProxy, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, wrongCreds, httpProxyVer, useTls)
					if err != nil {
						t.Fatal(err)
					}
					if responseProbeResist.StatusCode != responseReference.StatusCode {
						t.Fatalf("Expected response: %d, Got: %d\n",
							responseReference.StatusCode, responseProbeResist.StatusCode)
					}
					if err = responsesAreEqual(responseProbeResist, responseReference); err != nil {
						t.Fatal(err)
					}
					if err = responsesAreEqual(responseProbeResist, responseForwardProxy); err == nil {
						t.Fatal("Responses from servers with and without forwardproxy are expected to be different.")
					}
				}
				// request self
				for _, resource := range testResources {
					if httpTargetVer != httpProxyVer {
						continue
					}
					responseProbeResist, err := connectAndGetViaProxy(caddyForwardProxyProbeResist.addr, resource, caddyForwardProxyProbeResist.addr, httpTargetVer, wrongCreds, httpProxyVer, useTls)
					if err != nil {
						t.Fatal(err)
					}
					// get response from reference server without forwardproxy and compare them
					responseReference, err := connectAndGetViaProxy(caddyDummyProbeResist.addr, resource, caddyDummyProbeResist.addr, httpTargetVer, wrongCreds, httpProxyVer, useTls)
					if err != nil {
						t.Fatal(err)
					}
					// as a sanity check, get 407 from simple authenticated forwardproxy
					responseForwardProxy, err := connectAndGetViaProxy(caddyForwardProxyAuth.addr, resource, caddyForwardProxyAuth.addr, httpTargetVer, wrongCreds, httpProxyVer, useTls)
					if err != nil {
						t.Fatal(err)
					}
					if responseProbeResist.StatusCode != http.StatusOK {
						t.Fatalf("Expected response: 200 StatusOK, Got: %d\n",
							responseProbeResist.StatusCode)
					}
					if err = responsesAreEqual(responseProbeResist, responseReference); err != nil {
						t.Fatal(err)
					}
					if err = responsesAreEqual(responseProbeResist, responseForwardProxy); err == nil {
						t.Fatal("Responses from servers with and without forwardproxy are expected to be different.")
					}
				}
			}
		}
	}
}

// test that responses on http redirect port are same
func TestConnectAuthWrongProbeResistRedir(t *testing.T) {
	useTls := false
	httpProxyVer := "HTTP/1.1"
	for _, wrongCreds := range credentialsWrong {
		for _, httpTargetVer := range testHttpTargetVersions {
			// request test target
			for _, resource := range testResources {
				responseProbeResist, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, stripPort(caddyForwardProxyProbeResist.addr)+":"+caddyForwardProxyProbeResist.HTTPRedirectPort,
					httpTargetVer, wrongCreds, httpProxyVer, useTls)
				if err != nil {
					t.Fatal(err)
				}
				// get response from reference server without forwardproxy and compare them
				responseReference, err := connectAndGetViaProxy(caddyTestTarget.addr, resource, stripPort(caddyDummyProbeResist.addr)+":"+caddyDummyProbeResist.HTTPRedirectPort,
					httpTargetVer, wrongCreds, httpProxyVer, useTls)
				if err != nil {
					t.Fatal(err)
				}
				if responseProbeResist.StatusCode != responseReference.StatusCode {
					t.Fatalf("Expected response: %d, Got: %d\n",
						responseReference.StatusCode, responseProbeResist.StatusCode)
				}
				if err = responsesAreEqual(responseProbeResist, responseReference); err != nil {
					t.Fatal(err)
				}
			}
			// request self
			for _, resource := range testResources {
				responseProbeResist, err := connectAndGetViaProxy(caddyForwardProxyProbeResist.addr, resource, stripPort(caddyForwardProxyProbeResist.addr)+":"+caddyForwardProxyProbeResist.HTTPRedirectPort,
					httpTargetVer, wrongCreds, httpProxyVer, useTls)
				if err != nil {
					t.Fatal(err)
				}
				// get response from reference server without forwardproxy and compare them
				responseReference, err := connectAndGetViaProxy(caddyDummyProbeResist.addr, resource, stripPort(caddyDummyProbeResist.addr)+":"+caddyDummyProbeResist.HTTPRedirectPort,
					httpTargetVer, wrongCreds, httpProxyVer, useTls)
				if err != nil {
					t.Fatal(err)
				}
				if responseProbeResist.StatusCode != responseReference.StatusCode {
					t.Fatalf("Expected response: %d, Got: %d\n",
						responseReference.StatusCode, responseProbeResist.StatusCode)
				}
				if err = responsesAreEqual(responseProbeResist, responseReference); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

// returns nil if are equal
func responsesAreEqual(res1, res2 *http.Response) error {
	if res1 == nil {
		return errors.New("res1 is nil")
	}
	if res2 == nil {
		return errors.New("res2 is nil")
	}
	if res1.Status != res2.Status {
		return errors.New("Status is different")
	}
	if res1.StatusCode != res2.StatusCode {
		return errors.New("StatusCode is different")
	}

	if res1.ProtoMajor != res2.ProtoMajor {
		return errors.New("ProtoMajor is different")
	}

	if res1.Close != res2.Close {
		return errors.New("Close is different")
	}

	if res1.ProtoMinor != res2.ProtoMinor {
		return errors.New("ProtoMinor is different")
	}

	if res1.ContentLength != res2.ContentLength {
		return errors.New("ContentLength is different")
	}

	if res1.Uncompressed != res2.Uncompressed {
		return errors.New("Uncompressed is different")
	}
	if res1.Proto != res2.Proto {
		return errors.New("Proto is different")
	}
	if len(res1.TransferEncoding) != len(res2.TransferEncoding) {
		return errors.New("TransferEncodings have different length")
	}

	// returns "" if equal
	stringSlicesAreEqual := func(s1, s2 []string) string {
		if s1 == nil && s2 == nil {
			return ""
		}

		if s1 == nil {
			return "s1 is nil, whereas s2 is not"
		}
		if s2 == nil {
			return "s2 is nil, whereas s1 is not"
		}

		if len(s1) != len(s2) {
			return fmt.Sprintf("different length: %d vs %d", len(s1), len(s2))
		}
		for i := range s1 {
			if s1[i] != s2[i] {
				return fmt.Sprintf("different string at position %d: %s vs %s", i, s1[i], s2[i])
			}
		}
		return ""
	}

	errStr := stringSlicesAreEqual(res1.TransferEncoding, res2.TransferEncoding)
	if errStr != "" {
		return errors.New("TransferEncodings are different: " + errStr)
	}

	if len(res1.Header) != len(res2.Header) {
		return errors.New("Headers have different length")
	}
	for k1, v1 := range res1.Header {
		k1Lower := strings.ToLower(k1)
		if k1Lower == "date" {
			continue
		}
		v2, ok := res2.Header[k1]
		if !ok {
			return errors.New(fmt.Sprintf("Header \"%s: %s\" is absent in res2", k1, v1))
		}
		if k1Lower == "location" {
			for i, h := range v2 {
				v2[i] = removeAddressesStr(h)
			}
			for i, h := range v1 {
				v1[i] = removeAddressesStr(h)
			}
		}
		if errStr = stringSlicesAreEqual(v1, v2); errStr != "" {
			return errors.New(fmt.Sprintf("Header \"%s\" is different: %s", k1, errStr))
		}
	}
	// Compare bodies
	buf1, err1 := ioutil.ReadAll(res1.Body)
	buf2, err2 := ioutil.ReadAll(res2.Body)
	n1 := len(buf1)
	n2 := len(buf2)
	makeBodyError := func(s string) error {
		return errors.New(fmt.Sprintf("Bodies are different: %s. n1 = %d, n2 = %d. err1 = %v, err2 = %v. buf1 = %s, buf2 = %s",
			s, n1, n2, err1, err2, buf1[:n1], buf2[:n2]))
	}
	if n2 != n1 {
		return makeBodyError("Body sizes are different")
	}
	buf1 = removeAddressesByte(buf1[:n1])
	buf2 = removeAddressesByte(buf2[:n1])
	for i := range buf1 {
		if buf1[i] != buf2[i] {
			return makeBodyError(fmt.Sprintf("Mismatched character %d", i))
		}
	}
	if err1 != nil || err2 != nil {
		return makeBodyError("Unexpected Read errors")
	}
	return nil
}

// Responses from forwardproxy + proberesist and generic caddy can have different addresses present in headers.
// To avoid false positives - remove addresses before comparing.
func removeAddressesByte(b []byte) []byte {
	b = bytes.Replace(b, []byte(caddyForwardProxyProbeResist.addr),
		bytes.Repeat([]byte{'#'}, len(caddyForwardProxyProbeResist.addr)), -1)
	b = bytes.Replace(b, []byte(caddyDummyProbeResist.addr),
		bytes.Repeat([]byte{'#'}, len(caddyDummyProbeResist.addr)), -1)
	return b
}

func removeAddressesStr(s string) string {
	return string(removeAddressesByte([]byte(s)))
}
