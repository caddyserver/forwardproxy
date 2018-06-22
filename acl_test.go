package forwardproxy

import (
	"net/http"
	"testing"
)

/*
test port blocking working
test blacklist allowed
test blacklist refused with correct status

*/

func TestWhitelistAllowing(t *testing.T) {
	useTls := true
	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyWhiteListing.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestWhitelistBlocking(t *testing.T) {
	useTls := true
	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyHTTPTestTarget.addr, resource, caddyForwardProxyWhiteListing.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}

	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy("google.com:6451", resource, caddyForwardProxyWhiteListing.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}
}

func TestLocalhostDefaultForbidden(t *testing.T) {
	useTls := true
	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy("localhost:6451", resource, caddyForwardProxyNoBlacklistOverride.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}

	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy("127.0.0.1:808", resource, caddyForwardProxyNoBlacklistOverride.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}

	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy("[::1]:8080", resource, caddyForwardProxyNoBlacklistOverride.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}
}

func TestLocalNetworksDefaultForbidden(t *testing.T) {
	useTls := true
	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy("10.0.0.0:80", resource, caddyForwardProxyNoBlacklistOverride.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}

	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy("127.222.34.1:443", resource, caddyForwardProxyNoBlacklistOverride.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}

	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy("172.16.0.1:8080", resource, caddyForwardProxyNoBlacklistOverride.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}

	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy("192.168.192.168:888", resource, caddyForwardProxyNoBlacklistOverride.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}
}

func TestBlacklistBlocking(t *testing.T) {
	useTls := true
	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(blacklistedDomain, resource, caddyForwardProxyBlackListing.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}

	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(blacklistedIPv4, resource, caddyForwardProxyBlackListing.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}

	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(blacklistedIPv6, resource, caddyForwardProxyBlackListing.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if response.StatusCode != http.StatusForbidden {
				t.Fatal("Expected response \"403 Forbidden\", got:", response.StatusCode)
			}
		}
	}
}

func TestBlacklistAllowing(t *testing.T) {
	useTls := true
	for _, httpTargetVer := range testHttpVersions {
		for _, resource := range testResources {
			response, err := getViaProxy(caddyTestTarget.addr, resource, caddyForwardProxyBlackListing.addr, httpTargetVer,
				"", useTls)
			if err != nil {
				t.Fatal(err)
			} else if err = responseExpected(response, caddyTestTarget.contents[resource]); err != nil {
				t.Fatal(err)
			}
		}
	}
}
