// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyauthimported

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

// [POC] Code is the same as forwardproxy's basicauth former implementation
func getCredsFromHeader(r *http.Request) (string, string, error) {
	pa := strings.Split(r.Header.Get("Proxy-Authorization"), " ")
	if len(pa) != 2 {
		return "", "", errors.New("Proxy-Authorization is required! Expected format: <type> <credentials>")
	}
	if strings.ToLower(pa[0]) != "basic" {
		return "", "", errors.New("auth type is not supported")
	}
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(pa[1])))
	_, _ = base64.StdEncoding.Decode(buf, []byte(pa[1])) // should not err ever since we are decoding a known good input // TODO true?
	credarr := strings.Split(string(buf), ":")

	return credarr[0], credarr[1], nil
}

// Authenticate validates the user credentials in req and returns the user, if valid.
// [POC] Same code as caddy's basicAuth, but it doesn't write anything on the ResponseWriter
// Needs upstreaming, in case, to keep the code inside caddy.
func (hba HTTPBasicAuth) AuthenticateNoCredsPrompt(req *http.Request) (caddyauth.User, bool, error) {
	username, plaintextPasswordStr, err := getCredsFromHeader(req)
	if err != nil {
		return caddyauth.User{}, false, err
	}

	account, accountExists := hba.Accounts[username]
	if !accountExists {
		// don't return early if account does not exist; we want
		// to try to avoid side-channels that leak existence, so
		// we use a fake password to simulate realistic CPU cycles
		account.password = hba.fakePassword
	}

	same, err := hba.correctPassword(account, []byte(plaintextPasswordStr))
	if err != nil || !same || !accountExists {
		return caddyauth.User{ID: username}, false, err
	}

	return caddyauth.User{ID: username}, true, nil
}

// [POC] Lifted/adapted from modules/caddyhttp/caddyauth/caddyfile.go#parseCaddyfile()
// IDK how to reuse that method directly, honestly. Also, I don't have a httpcaddyfile.Helper as
// in the original code, but a caddyfile.Dispenser seems to work.
func ParseCaddyfileForHTTPBasicAuth(h *caddyfile.Dispenser) (*HTTPBasicAuth, error) {
	// [POC] removed code
	// h.Next() // consume directive name

	// // "basicauth" is deprecated, replaced by "basic_auth"
	// if h.Val() == "basicauth" {
	// 	caddy.Log().Named("config.adapter.caddyfile").Warn("the 'basicauth' directive is deprecated, please use 'basic_auth' instead!")
	// }

	var ba HTTPBasicAuth
	ba.HashCache = new(Cache)

	var cmp caddyauth.Comparer
	args := h.RemainingArgs()

	var hashName string
	switch len(args) {
	case 0:
		hashName = "bcrypt"
	case 1:
		hashName = args[0]
	case 2:
		hashName = args[0]
		ba.Realm = args[1]
	default:
		return nil, h.ArgErr()
	}

	switch hashName {
	case "bcrypt":
		cmp = caddyauth.BcryptHash{}
	default:
		return nil, h.Errf("unrecognized hash algorithm: %s", hashName)
	}

	ba.HashRaw = caddyconfig.JSONModuleObject(cmp, "algorithm", hashName, nil)

	for h.NextBlock(0) {
		username := h.Val()

		var b64Pwd string
		h.Args(&b64Pwd)
		if h.NextArg() {
			return nil, h.ArgErr()
		}

		if username == "" || b64Pwd == "" {
			return nil, h.Err("username and password cannot be empty or missing")
		}

		ba.AccountList = append(ba.AccountList, Account{
			Username: username,
			Password: b64Pwd,
		})
	}

	// [POC] Removed code
	// return Authentication{
	// 	ProvidersRaw: caddy.ModuleMap{
	// 		"http_basic": caddyconfig.JSON(ba, nil),
	// 	},
	// }, nil

	// [POC] Added code
	return &ba, nil
}
