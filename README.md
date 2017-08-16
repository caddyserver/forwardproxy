# ForwardProxy plugin for Caddy webserver
 
This plugin enables Caddy webserver to act as a ForwardProxy for http/2.0 and http/1.1 requests
(http/1.0 might work, but is untested).

## ForwardProxy Caddyfile directives
To simply enable forward proxy without authentication just include the ```forwardproxy``` directive in your Caddyfile.

To do more advanced things, you may use expanded syntax:
```
forwardproxy {
    basicauth caddyuser1 0NtCL2JPJBgPPMmlPcJ
    basicauth caddyuser2 秘密
    ports 80 443
    hide_ip
    experimental_probe_resist secretlink-7qS4+3dqm.localhost
    response_timeout 30
    dial_timeout 30
}
```
Warning: all directives are subject to changes!
* basicauth user password  
Sets basic HTTP auth credentials. This directive may be repeated multiple times.  
Default: no auth required.
* ports integer integer...  
Whitelists ports forwardproxy will HTTP CONNECT to.  
Default: no restrictions.
* hide_ip  
If set, forwardproxy will not add user's IP to "Forwarded:" header.  
Default: no hiding, "_Forwarded: for="useraddress"_" will be sent out.
* experimental_probe_resist secretlink.tld  
EXPERIMENTAL, HERE BE DRAGONS.  
Attempts to hide the fact that the site is a forwardproxy.
Proxy will no longer respond with _"407 Proxy Authentication Required"_ if credentials are incorrect or absent,
and will attempt to mimic generic forwardproxy-less Caddy server in other regards.  
Not all clients(browsers) are able to be configured to send credentials right away,
and only provide credentials after receiving 407.
To work around this, we will use a secret link - the only link that will trigger 407 response,
prompting browsers to request credentials from users and cache them for the rest of the session.  
It is possible to use any top level domain, but for secrecy reasons it is highly recommended to use .localhost.  
Probing resistance works(and makes sense) only if basicauth is set up.  
Default: no probing resistance.
* response_timeout integer  
Sets timeout (in seconds) for HTTP requests made by proxy on behalf of users (does not affect CONNECT requests)  
Default: no timeout(other timeouts will eventually close the connection).
* dial_timeout integer  
Sets timeout (in seconds) for establishing TCP connection to target website. Affects all requests.  
Default: 20 seconds.

### License
Licensed under the [Apache License](LICENSE)

Initial version of this plugin was developed by Google.
Disclaimer: This is not an official Google product.
