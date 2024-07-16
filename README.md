# Secure forward proxy for the Caddy web server

This package registers the `http.handlers.forward_proxy` module, which acts as an HTTPS proxy for accessing remote networks.

## :warning: Experimental!

This module is EXPERIMENTAL. We need more users to test this module for bugs and weaknesses before we recommend its use from within surveilled networks or regions with active censorship. Do not rely on this code in situations where personal safety, freedom, or privacy are at risk.

**You can help by:**

- Safely deploying this module
- Trying to break it
- Contributing to the code and tests in this repo to make it better

We are also seeking experienced maintainers who have experience with these kinds of technologies and who are interested in continuing its development.

**Expect breaking changes.**

## Features

- HTTP/1.1, HTTP/2, and HTTP/3 support
- Authentication
- Access control lists
- Optional probe resistance
- PAC file


## Introduction

This Caddy module allows you to use your web server as a proxy server, configurable by numerous HTTP clients such as operating systems, web browsers, mobile devices, and apps. However, the feature set of each client varies widely, as does their correctness and security guarantees. You will have to be aware of each clients' individual weaknesses or shortcomings.


## Quick start

First, you will have to know [how to use Caddy](https://caddyserver.com/docs/getting-started).

Build Caddy with this plugin. You can add it from [Caddy's download page](https://caddyserver.com/download) or build it yourself with [xcaddy](https://github.com/caddyserver/xcaddy):

```
$ xcaddy build --with github.com/caddyserver/forwardproxy
```

Most people prefer the [Caddyfile](https://caddyserver.com/docs/caddyfile) for configuration. You can stand up a simple, wide-open unauthenticated forward proxy like this:

```
example.com
route {
	# UNAUTHENTICATED! USE ONLY FOR TESTING
	forward_proxy
}
```

(Obviously, replace `example.com` with your domain name which is pointed at your machine.)

Because `forward_proxy` is not a standard directive, its ordering relative to other handler directives is not defined, so we put it inside a `route` block. You can alternatively do something like this:

```
{
	order forward_proxy before file_server
}
example.com
# UNAUTHENTICATED! USE ONLY FOR TESTING
forward_proxy
```

to define its position globally; then you don't need `route` blocks. The correct order is up to you and depends on your config.

This plugin enables [Caddy](https://caddyserver.com) to act as a forward proxy, with support for HTTP/3, HTTP/2, and HTTP/1.1 requests. HTTP/3 and HTTP/2 will usually improve performance due to multiplexing.

Forward proxy plugin includes common features like Access Control Lists and authentication, as well as some unique features to assist with security and privacy. Default configuration of forward proxy is compliant with existing HTTP standards, but some features force plugin to exhibit non-standard but non-breaking behavior to preserve privacy.

Probing resistance—one of the signature features of this plugin—attempts to hide the fact that your webserver is also a forward proxy, helping the proxy to stay under the radar. Eventually, forwardproxy plugin implemented a simple *reverse* proxy (`upstream https://user:password@next-hop.com` in Caddyfile) just so users may take advantage of `probe_resistance` when they need a reverse proxy (for example, to build a chain of proxies). Reverse proxy implementation will stay simple, and if you need a powerful reverse proxy, look into Caddy's standard `proxy` directive.

For a complete list of features and their usage, see Caddyfile syntax:

## Caddyfile Syntax (Server Configuration)

The simplest way to enable the forward proxy without authentication just include the `forward_proxy` directive in your Caddyfile. However, this allows anyone to use your server as a proxy, which might not be desirable.

The `forward_proxy` directive has no default order and must be used within a `route` directive to explicitly specify its order of evaluation. In the Caddyfile the addresses must start with `:443` for the `forward_proxy` to work for proxy requests of all origins.

Here's an example of all properties in use (note that the syntax is subject to change):

```
:443, example.com
route {
	forward_proxy {
		basic_auth user1 0NtCL2JPJBgPPMmlPcJ
		basic_auth user2 密码
		ports     80 443
		hide_ip
		hide_via
		probe_resistance secret-link-kWWL9Q.com # alternatively you can use a real domain, such as caddyserver.com
		serve_pac        /secret-proxy.pac
		dial_timeout     30
		upstream         https://user:password@extra-upstream-hop.com
		acl {
			allow     *.caddyserver.com
			deny      192.168.1.1/32 192.168.0.0/16 *.prohibitedsite.com *.localhost
			allow     ::1/128 8.8.8.8 github.com *.github.io
			allow_file /path/to/whitelist.txt
			deny_file  /path/to/blacklist.txt
			allow     all
			deny      all # unreachable rule, remaining requests are matched by `allow all` above
		}
	}
	file_server
}
```

(The square brackets `[ ]` indicate values you should replace; do not actually include the brackets.)

### Security

- `basic_auth [user] [password]`  
  Sets basic HTTP auth credentials. This property may be repeated multiple times. Note that this is different from Caddy's built-in `basic_auth` directive. BE SURE TO CHECK THE NAME OF THE SITE THAT IS REQUESTING CREDENTIALS BEFORE YOU ENTER THEM.

  Default: no authentication required.
- `probe_resistance [secretlink.tld]`  
  Attempts to hide the fact that the site is a forward proxy.
  Proxy will no longer respond with "407 Proxy Authentication Required" if credentials are incorrect or absent,
  and will attempt to mimic a generic Caddy web server as if the forward proxy is not enabled.

  Probing resistance works (and makes sense) only if `basic_auth` is set up.
  To use your proxy with probe resistance, supply your `basic_auth` credentials to your client configuration.
  If your proxy client(browser, operating system, browser extension, etc)
  allows you to preconfigure credentials, and sends credentials preemptively, you do not need secret link.

  If your proxy client does not preemptively send credentials, you will have to visit your secret link in your browser to trigger the authentication.
  Make sure that specified domain name is visitable, does not contain uppercase characters, does not start with dot, etc.
  Only this address will trigger a 407 response, prompting browsers to request credentials from user and cache them for the rest of the session.

  Default: no probing resistance.

### Privacy

- `hide_ip`  
  If set, forwardproxy will not add user's IP to "Forwarded:" header.
  
  WARNING: there are other side-channels in your browser, that you might want to eliminate, such as WebRTC, see [here](https://www.ivpn.net/knowledgebase/158/My-IP-is-being-leaked-by-WebRTC-How-do-I-disable-it.html) how to disable it.
  
  Default: no hiding; `Forwarded: for="useraddress"` will be sent out.
- `hide_via`  
  If set, forwardproxy will not add Via header, and prevents simple way to detect proxy usage.

  WARNING: there are other side-channels to determine this.

  Default: no hiding; Header in form of `Via: 2.0 caddy` will be sent out.

### Access Control

- `ports [integer] [integer]...`  
  Specifies ports forwardproxy will whitelist for all requests. Other ports will be forbidden.

  Default: no restrictions.
-     acl {  
    	acl_directive  
    	...  
    	acl_directive  
      }
  Specifies **order** and rules for allowed destination IP networks, IP addresses and hostnames.
  The hostname in each forwardproxy request will be resolved to an IP address,
  and caddy will check the IP address and hostname against the directives in order until a directive matches the request.
  
  `acl_directive` may be:  
    - `allow [ip or subnet or hostname] [ip or subnet or hostname]...`
    - `allow_file /path/to/whitelist.txt`
    - `deny [ip or subnet or hostname] [ip or subnet or hostname]...`
    - `deny_file /path/to/blacklist.txt`
  
  If you don't want unmatched requests to be subject to the default policy, you could finish
  your acl rules with one of the following to specify action on unmatched requests:
    - `allow all`
    - `deny all`

  For `hostname`, you can specify `*.` as a prefix to match domain and subdomains. For example,
  `*.caddyserver.com` will match `caddyserver.com`, `subdomain.caddyserver.com`, but not `fakecaddyserver.com`.
  Note that hostname rules, matched early in the chain, will override later IP rules,
  so it is advised to put IP rules first, unless domains are highly trusted and should override the
  IP rules. Also note that domain-based blacklists are easily circumventable by directly specifying the IP.
  
  For `allow_file`/`deny_file` directives, syntax is the same, and each entry must be separated by newline.
  
  This policy applies to all requests except requests to the proxy's own domain and port.
  Whitelisting/blacklisting of ports on per-host/IP basis is not supported.

  Default policy:

  ```
  acl {  
  	deny 10.0.0.0/8 127.0.0.0/8 172.16.0.0/12 192.168.0.0/16 ::1/128 fe80::/10  
  	allow all  
  }
  ```
  
  Default deny rules intend to prohibit access to localhost and local networks and may be expanded in future.

### Timeouts

- `dial_timeout [integer]`  
  Sets timeout (in seconds) for establishing TCP connection to target website. Affects all requests.

  Default: 20 seconds.

### Other

- `serve_pac [/path.pac]`  
  Generate (in-memory) and serve a [Proxy Auto-Config](https://en.wikipedia.org/wiki/Proxy_auto-config) file on given path. If no path is provided, the PAC file will be served at `/proxy.pac`. NOTE: If you enable probe_resistance, your PAC file should also be served at a secret location; serving it at a predictable path can easily defeat probe resistance.

  Default: no PAC file will be generated or served by Caddy (you still can manually create and serve proxy.pac like a regular file).
- `upstream [https://username:password@upstreamproxy.site:443]`  
  Sets upstream proxy to route all forwardproxy requests through it.
  This setting does not affect non-forwardproxy requests nor requests with wrong credentials.
  Upstream is incompatible with `acl` and `ports` subdirectives.

  Supported schemes to remote host: https.

  Supported schemes to localhost: socks5, http, https (certificate check is ignored).

  Default: no upstream proxy.

## Get forwardproxy
### Download prebuilt binary
Binaries are at https://caddyserver.com/download  
Don't forget to add `http.forwardproxy` plugin.

### Build from source

0. Install latest Golang 1.20 or above and set `export GO111MODULE=on`
1. `go install github.com/caddyserver/forwardproxy/cmd/caddy@latest`  
   Built `caddy` binary will be stored in $GOPATH/bin.  

## Client Configuration

Please be aware that client support varies widely, and there are edge cases where clients may not use the proxy when it should or could. It's up to you to be aware of these limitations.

The basic configuration is simply to use your site address and port (usually for all protocols - HTTP, HTTPS, etc). You can also specify the .pac file if you enabled that.

Read [this blog post](https://sfrolov.io/2017/08/secure-web-proxy-client-en) about how to configure your specific client.

## License

Licensed under the [Apache License](LICENSE)

## Disclaimers

USE AT YOUR OWN RISK. THIS IS DELIVERED AS-IS. By using this software, you agree and assert that authors, maintainers, and contributors of this software are not responsible or liable for any risks, costs, or problems you may encounter. Consider your threat model and be smart. If you find a flaw or bug, please submit a patch and help make things better!

Initial version of this plugin was developed by Google. This is not an official Google product.
