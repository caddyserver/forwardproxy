# Secure forward proxy plugin for the Caddy web server

[![Build Status](https://travis-ci.org/caddyserver/forwardproxy.svg?branch=master)](https://travis-ci.org/caddyserver/forwardproxy)  
[![Join the chat at https://gitter.im/forwardproxy/Lobby](https://badges.gitter.im/forwardproxy/Lobby.svg)](https://gitter.im/forwardproxy/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)


This plugin enables [Caddy](https://caddyserver.com) to act as a forward proxy (as opposed to reverse proxy, Caddy's standard `proxy` directive) for HTTP/2.0 and HTTP/1.1 requests (HTTP/1.0 might work, but is untested).

## Caddyfile Syntax (Server Configuration)

The simplest way to enable the forward proxy without authentication just include the `forwardproxy` directive in your Caddyfile. However, this allows anyone to use your server as a proxy, which might not be desirable.

Open a block for more control; here's an example of all properties in use (note that the syntax is subject to change):

```
forwardproxy {
    basicauth user1 0NtCL2JPJBgPPMmlPcJ
    basicauth user2 密码
    ports     80 443
    hide_ip
    hide_via
    probe_resistance secretlink.localhost
    serve_pac        /secret-proxy.pac
    response_timeout 30
    dial_timeout     30
    upstream         https://user:password@extra-upstream-hop.com
    acl {
      allow     *.caddyserver.com
      deny      192.168.1.1/32 192.168.0.0/16 *.prohibitedsite.com *.localhost
      allow     ::1/128 8.8.8.8 github.com *.github.io
      allowfile /path/to/whitelist.txt
      denyfile  /path/to/blacklist.txt
      allow     all
      deny      all // unreachable rule, remaining requests are matched by `allow all`
    }
}
```

(The square brackets `[ ]` indicate values you should replace; do not actually include the brackets.)

##### Security

- **basicauth [user] [password]**  
Sets basic HTTP auth credentials. This property may be repeated multiple times. Note that this is different from Caddy's built-in `basicauth` directive. BE SURE TO CHECK THE NAME OF THE SITE THAT IS REQUESTING CREDENTIALS BEFORE YOU ENTER THEM.  
_Default: no authentication required._

- **probe_resistance [secretlink.tld]**  
Attempts to hide the fact that the site is a forward proxy.
Proxy will no longer respond with "407 Proxy Authentication Required" if credentials are incorrect or absent,
and will attempt to mimic a generic Caddy web server as if the forward proxy is not enabled.  
Probing resistance works (and makes sense) only if basicauth is set up.
To use your proxy with probe resistance, supply your basicauth credentials to your client configuration.
If your proxy client(browser, operating system, browser extension, etc)
allows you to preconfigure credentials, and sends credentials preemptively, you do not need secret link.  
If your proxy client does not preemptively send credentials, you will have to visit your secret link in your browser to trigger the authentication.
Make sure that specified domain name is visitable, does not contain uppercase characters, does not start with dot, etc.
Only this address will trigger a 407 response, prompting browsers to request credentials from user and cache them for the rest of the session.
It is possible to use any top level domain, but for secrecy reasons it is highly recommended to use `.localhost`.  
_Default: no probing resistance._

##### Privacy

- **hide_ip**  
If set, forwardproxy will not add user's IP to "Forwarded:" header.  
WARNING: there are other side-channels in your browser, that you might want to eliminate, such as WebRTC, see [here](https://www.ivpn.net/knowledgebase/158/My-IP-is-being-leaked-by-WebRTC-How-do-I-disable-it.html) how to disable it.  
_Default: no hiding; `Forwarded: for="useraddress"` will be sent out._

- **hide_via**  
If set, forwardproxy will not add Via header, and prevents simple way to detect proxy usage.  
WARNING: there are other side-channels to determine this.  
_Default: no hiding; Header in form of `Via: 2.0 caddy` will be sent out._

##### Access Control

- **ports [integer] [integer]...**  
Specifies ports forwardproxy will whitelist for all requests. Other ports will be forbidden.  
_Default: no restrictions._

- **acl {  
&nbsp;&nbsp;&nbsp;&nbsp;acl_directive  
&nbsp;&nbsp;&nbsp;&nbsp;...  
&nbsp;&nbsp;&nbsp;&nbsp;acl_directive  
}**  
Specifies **order** and rules for allowed destination IP networks, IP addresses and hostnames.
The hostname in each forwardproxy request will be resolved to an IP address,
and caddy will check the IP address and hostname against the directives in order until a directive matches the request.
acl_directive may be:
  - **allow [ip or subnet or hostname] [ip or subnet or hostname]...**
  - **allowfile /path/to/whitelist.txt**
  - **deny [ip or subnet or hostname] [ip or subnet or hostname]...**
  - **denyfile /path/to/blacklist.txt**

  If you don't want unmatched requests to be subject to the default policy, you could finish
  your acl rules with one of the following to specify action on unmatched requests:
  - **allow all**
  - **deny all**
  
  For hostname, you can specify `*.` as a prefix to match domain and subdomains. For example,
  `*.caddyserver.com` will match caddyserver.com, subdomain.caddyserver.com, but not fakecaddyserver.com.
  Note that hostname rule, matched early in the chain, will override later IP rules,
  so it is advised to put IP rules first, unless domains are highly trusted and should override the
  IP rules. Also note that domain-based blacklists are easily circumventable by directly specifying the IP.  
  For `allowfile`/`denyfile` directives, syntax is the same, and each entry must be separated by newline.  
  This policy applies to all requests except requests to the proxy's own domain and port.
  Whitelisting/blacklisting of ports on per-host/IP basis is not supported.  
_Default policy:_  
acl {  
&nbsp;&nbsp;&nbsp;&nbsp;deny 10.0.0.0/8 127.0.0.0/8 172.16.0.0/12 192.168.0.0/16 ::1/128 fe80::/10  
&nbsp;&nbsp;&nbsp;&nbsp;allow all  
}  
_Default deny rules intend to prohibit access to localhost and local networks and may be expanded in future._

##### Timeouts

- **response_timeout [integer]**  
Sets timeout (in seconds) to get full response for HTTP requests made by proxy on behalf of users (does not affect `CONNECT`-method requests).  
_Default: no timeout._

- **dial_timeout [integer]**  
Sets timeout (in seconds) for establishing TCP connection to target website. Affects all requests.  
_Default: 20 seconds._

##### Other

- **serve_pac [/path.pac]**  
Generate (in-memory) and serve a [Proxy Auto-Config](https://en.wikipedia.org/wiki/Proxy_auto-config) file on given path. If no path is provided, the PAC file will be served at `/proxy.pac`. NOTE: If you enable probe_resistance, your PAC file should also be served at a secret location; serving it at a predictable path can easily defeat probe resistance.  
_Default: no PAC file will be generated or served by Caddy (you still can manually create and serve proxy.pac like a regular file)._

- **upstream [https://username:password@upstreamproxy.site:443]**  
Sets upstream proxy to route all forwardproxy requests through it.
This setting does not affect non-forwardproxy requests nor requests with wrong credentials.
Upstream is incompatible with `acl` and `ports` subdirectives.  
Supported schemes to remote host: https.  
Supported schemes to localhost: socks5, http, https(certificate check is ignored).  
_Default: no upstream proxy._

## Get forwardproxy
#### Download prebuilt binary
Binaries are at https://caddyserver.com/download  
Don't forget to add "http.forwardproxy" plugin.

#### Build from source

0. Install latest stable Golang
1. Download caddy webserver and forwardproxy plugin:
   ```bash
   go get -d -u -t github.com/caddyserver/forwardproxy/... github.com/mholt/caddy/...
   ```
2. Add 'import _ "github.com/caddyserver/forwardproxy/"' to caddy/main.go: 
   ```bash
   sed -i 's/^import/import _ "github\.com\/caddyserver\/forwardproxy"\nimport/' ${GOPATH:-~/go}/src/github.com/mholt/caddy/caddy/main.go
   ```
3. Build it:
   ```bash
   cd ${GOPATH:-~/go}/src/github.com/mholt/caddy/caddy/
   go build
   ```

If it won't build, try reinstalling Golang, removing $GOPATH, you know, the usual dance.
If version of caddy in trunk does not work, you can try building latest [stable release](https://github.com/mholt/caddy/releases).

## Client Configuration

Please be aware that client support varies widely, and there are edge cases where clients may not use the proxy when it should or could. It's up to you to be aware of these limitations.

The basic configuration is simply to use your site address and port (usually for all protocols - HTTP, HTTPS, etc). You can also specify the .pac file if you enabled that.

Read [this blog post](https://sfrolov.io/2017/08/secure-web-proxy-client-en) about how to configure your specific client.


## License

Licensed under the [Apache License](LICENSE)

## Disclaimers

USE AT YOUR OWN RISK. THIS IS DELIVERED AS-IS. By using this software, you agree and assert that authors, maintainers, and contributors of this software are not responsible or liable for any risks, costs, or problems you may encounter. Consider your threat model and be smart. If you find a flaw or bug, please submit a patch and help make things better!

Initial version of this plugin was developed by Google. This is not an official Google product.
