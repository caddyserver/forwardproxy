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

	"github.com/mholt/caddy"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("http", "forwardproxy string")
	err := setup(c)
	if err == nil {
		t.Fatal("Expected: failure. Got: success. Input: forwardproxy string")
	}

	testParsing := func(subdirectives []string, shouldSucceed bool) {
		input := "forwardproxy"
		if len(subdirectives) > 0 {
			input += " {\n"
			for _, s := range subdirectives {
				input += s + "\n"
			}
			input += "}"
		}
		c := caddy.NewTestController("http", input)
		err := setup(c)
		if shouldSucceed && err != nil {
			t.Fatalf("Expected: success. Got: %v. Input:\n%s\n", err, input)
		}
		if !shouldSucceed && err == nil {
			t.Fatalf("Expected: failure. Got: success. Input:\n%s\n", input)
		}
	}
	testParsing(nil, true)
	testParsing([]string{}, true)
	testParsing([]string{"qweqwe"}, false)
	testParsing([]string{"0"}, false)

	testParsing([]string{"basicauth john"}, true)
	testParsing([]string{"basicauth john \"\""}, true)
	testParsing([]string{"basicauth john", "basicauth john \"\""}, true)
	testParsing([]string{"basicauth john doe"}, true)
	testParsing([]string{"basicauth john doe foo"}, false)
	testParsing([]string{"basicauth john doe foo bar"}, false)
	testParsing([]string{"basicauth \"\" doe"}, false)
	testParsing([]string{"basicauth \"\" \"\""}, false)
	testParsing([]string{"basicauth 0"}, true)
	testParsing([]string{"basicauth 0 0"}, true)
	testParsing([]string{"basicauth 0 0 0"}, false)
	testParsing([]string{"basicauth 秘密"}, true)
	testParsing([]string{"basicauth 秘密 秘密"}, true)
	testParsing([]string{"basicauth 秘密 秘密 秘密"}, false)
	testParsing([]string{"basicauth cyrillic пароль"}, true)
	testParsing([]string{"basicauth john \"\"", "basicauth john doe", "basicauth 0 0", "basicauth 秘密 秘密", "basicauth cyrillic пароль"}, true)

	testParsing([]string{"ports"}, false)
	testParsing([]string{"ports 0"}, false)
	testParsing([]string{"ports 0 1"}, false)
	testParsing([]string{"ports -1"}, false)
	testParsing([]string{"ports hi!"}, false)
	testParsing([]string{"ports 11, 122, 33"}, false)
	testParsing([]string{"ports 11, 122, 33"}, false)
	testParsing([]string{"ports 11111 99999"}, false)
	testParsing([]string{"ports 11 12"}, true)
	testParsing([]string{"ports 1"}, true)
	testParsing([]string{"ports 1 11 111 332 324 6546 33333"}, true)
	testParsing([]string{"ports 1 11 111 332 324 6546 33333", "ports 1 11 111 332 324 6546 33333"}, false)
	testParsing([]string{"ports 1", "ports 2"}, false)

	testParsing([]string{"hide_ip"}, true)
	testParsing([]string{"hide_ip 0"}, false)
	testParsing([]string{"hide_ip 0 1"}, false)

	testParsing([]string{"hide_via"}, true)
	testParsing([]string{"hide_via 0"}, false)
	testParsing([]string{"hide_via 0 1"}, false)

	testParsing([]string{"probe_resistance"}, false)
	testParsing([]string{"probe_resistance local.host"}, false)
	testParsing([]string{"probe_resistance local.host very.local.host"}, false)
	testParsing([]string{"probe_resistance", "basicauth john doe"}, true)
	testParsing([]string{"probe_resistance local.host", "basicauth john doe"}, true)
	testParsing([]string{"probe_resistance local.host very.local.host", "basicauth john doe"}, false)

	testParsing([]string{"serve_pac"}, true)
	testParsing([]string{"serve_pac \"\""}, true)
	testParsing([]string{"serve_pac proxyautoconfig.pac"}, true)
	testParsing([]string{"serve_pac 1.pac 2.pac"}, false)

	testParsing([]string{"response_timeout"}, false)
	testParsing([]string{"response_timeout -1"}, false)
	testParsing([]string{"response_timeout 1 2"}, false)
	testParsing([]string{"response_timeout seven"}, false)
	testParsing([]string{"response_timeout 2"}, true)

	testParsing([]string{"dial_timeout"}, false)
	testParsing([]string{"dial_timeout -1"}, false)
	testParsing([]string{"dial_timeout 1 2"}, false)
	testParsing([]string{"dial_timeout seven"}, false)
	testParsing([]string{"dial_timeout 2"}, true)

	testParsing([]string{"upstream proxy.site"}, false)
	testParsing([]string{"upstream https://proxy.site https://proxy.site"}, false)
	testParsing([]string{"upstream http://localhost:1230"}, true)
	testParsing([]string{"upstream socks5://127.0.0.1:999"}, true)
	testParsing([]string{"upstream http://proxy.site"}, false)
	testParsing([]string{"upstream https://proxy.site https://proxy.site"}, false)
	testParsing([]string{"upstream https://proxy.site"}, true)
}
