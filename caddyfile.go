package forwardproxy

import (
	"encoding/base64"
	"log"
	"strconv"
	"strings"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	caddyauthimported "github.com/proofrock/forwardproxy/caddyauth_imported"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("forward_proxy", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var fp Handler
	err := fp.UnmarshalCaddyfile(h.Dispenser)
	return &fp, err
}

// EncodeAuthCredentials base64-encode credentials
func EncodeAuthCredentials(user, pass string) (result []byte) {
	raw := []byte(user + ":" + pass)
	result = make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(result, raw)
	return
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	args := d.RemainingArgs()
	if len(args) > 0 {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdirective := d.Val()
		args := d.RemainingArgs()
		switch subdirective {
		case "basic_auth":
			bam, err := caddyauthimported.ParseCaddyfileForHTTPBasicAuth(d)
			if err != nil {
				return err
			}
			h.BasicAuthModule = *bam
		case "hosts":
			if len(args) == 0 {
				return d.ArgErr()
			}
			if len(h.Hosts) != 0 {
				return d.Err("hosts subdirective specified twice")
			}
			h.Hosts = caddyhttp.MatchHost(args)
		case "ports":
			if len(args) == 0 {
				return d.ArgErr()
			}
			if len(h.AllowedPorts) != 0 {
				return d.Err("ports subdirective specified twice")
			}
			h.AllowedPorts = make([]int, len(args))
			for i, p := range args {
				intPort, err := strconv.Atoi(p)
				if intPort <= 0 || intPort > 65535 || err != nil {
					return d.Errf("ports are expected to be space-separated and in 0-65535 range, but got: %s", p)
				}
				h.AllowedPorts[i] = intPort
			}
		case "hide_ip":
			if len(args) != 0 {
				return d.ArgErr()
			}
			h.HideIP = true
		case "hide_via":
			if len(args) != 0 {
				return d.ArgErr()
			}
			h.HideVia = true
		case "probe_resistance":
			if len(args) > 1 {
				return d.ArgErr()
			}
			if len(args) == 1 {
				lowercaseArg := strings.ToLower(args[0])
				if lowercaseArg != args[0] {
					log.Println("[WARNING] Secret domain appears to have uppercase letters in it, which are not visitable")
				}
				h.ProbeResistance = &ProbeResistance{Domain: args[0]}
			} else {
				h.ProbeResistance = &ProbeResistance{}
			}
		case "serve_pac":
			if len(args) > 1 {
				return d.ArgErr()
			}
			if len(h.PACPath) != 0 {
				return d.Err("serve_pac subdirective specified twice")
			}
			if len(args) == 1 {
				h.PACPath = args[0]
				if !strings.HasPrefix(h.PACPath, "/") {
					h.PACPath = "/" + h.PACPath
				}
			} else {
				h.PACPath = "/proxy.pac"
			}
		case "dial_timeout":
			if len(args) != 1 {
				return d.ArgErr()
			}
			timeout, err := caddy.ParseDuration(args[0])
			if err != nil {
				return d.ArgErr()
			}
			if timeout < 0 {
				return d.Err("dial_timeout cannot be negative.")
			}
			h.DialTimeout = caddy.Duration(timeout)
		case "upstream":
			if len(args) != 1 {
				return d.ArgErr()
			}
			if h.Upstream != "" {
				return d.Err("upstream directive specified more than once")
			}
			h.Upstream = args[0]
		case "acl":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				aclDirective := d.Val()
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				var ruleSubjects []string
				var err error
				aclAllow := false
				switch aclDirective {
				case "allow":
					ruleSubjects = args
					aclAllow = true
				case "allow_file":
					if len(args) != 1 {
						return d.Err("allowfile accepts a single filename argument")
					}
					ruleSubjects, err = readLinesFromFile(args[0])
					if err != nil {
						return err
					}
					aclAllow = true
				case "deny":
					ruleSubjects = args
				case "deny_file":
					if len(args) != 1 {
						return d.Err("denyfile accepts a single filename argument")
					}
					ruleSubjects, err = readLinesFromFile(args[0])
					if err != nil {
						return err
					}
				default:
					return d.Err("expected acl directive: allow/allowfile/deny/denyfile." +
						"got: " + aclDirective)
				}
				ar := ACLRule{Subjects: ruleSubjects, Allow: aclAllow}
				h.ACL = append(h.ACL, ar)
			}
		default:
			return d.ArgErr()
		}
	}
	return nil
}
