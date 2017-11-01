# Secure forward proxy plugin for the Caddy web server
 
This plugin enables [Caddy](https://caddyserver.com) to act as a forward proxy (as opposed to reverse proxy, Caddy's standard `proxy` directive) for HTTP/2.0 and HTTP/1.1 requests (HTTP/1.0 might work, but is untested).

## Caddyfile syntax
To simply enable forward proxy without authentication just include the `forwardproxy` directive in your Caddyfile. However, this allows anyone to use your server as a proxy, which might not be desirable.

Open a block for more control; here's an example of all properties in use:

```
forwardproxy {
    basicauth user1 0NtCL2JPJBgPPMmlPcJ
    basicauth user2 秘密
    ports 80 443
    hide_ip
    probe_resistance secretlink-7qS4+3dqm.localhost
    serve_pac /secret-proxy.pac
    response_timeout 30
    dial_timeout 30
}
```

Note: at this point, all configuration settings are subject to change!

- **basicauth [user] [password]**  
Sets basic HTTP auth credentials. This property may be repeated multiple times. Note that this is different from Caddy's built-in `basicauth` directive. _Default: no authentication required._

- **ports [integer] [integer]...**  
Whitelists ports forwardproxy will HTTP CONNECT to. _Default: no restrictions._

- **hide_ip**
If set, forwardproxy will not add user's IP to "Forwarded:" header. _Default: no hiding; `Forwarded: for="useraddress"` will be sent out._

- **probe_resistance [secretlink.tld]**  
EXPERIMENTAL. (Here be dragons!) Attempts to hide the fact that the site is a forward proxy. Proxy will no longer respond with "407 Proxy Authentication Required" if credentials are incorrect or absent, and will attempt to mimic a generic Caddy web server as if the forward proxy is not configured. Since not all clients (browsers, operating systems, etc.) are able to be configured to send credentials right away (some only authenticate after receiving a 407), we will use a secret link. Only this address will trigger a 407 response, prompting browsers to request credentials from users and cache them for the rest of the session. It is possible to use any top level domain (tld), but for secrecy reasons it is highly recommended to use `.localhost`. Probing resistance works (and makes sense) only if basicauth is set up. To use your proxy with probe resistance, supply your basicauth credentials to your client configuration if possible. If your proxy client does not authenticate right away, you may then have to visit your secret link in your browser to trigger the authentication. BE SURE TO CHECK THE NAME OF THE SITE THAT IS REQUESTING CREDENTIALS BEFORE YOU ENTER THEM. _Default: no probing resistance._

- **serve_pac [/path.pac]**  
Generate (in-memory) and serve a [Proxy Auto-Config](https://en.wikipedia.org/wiki/Proxy_auto-config) file on given path. If no path is provided, the PAC file will be served at `/proxy.pac`. NOTE: If you enable probe_resistance, your PAC file should also be served at a secret location; serving it at a predictable path can easily defeat probe resistance. Default: no PAC file will be generated or served by Caddy (you still can manually create and serve proxy.pac like a regular file).

- **response_timeout [integer]**  
Sets timeout (in seconds) for HTTP requests made by proxy on behalf of users (does not affect `CONNECT`-method requests)  
_Default: no timeout (other timeouts will eventually close the connection)._

- **dial_timeout [integer]**  
Sets timeout (in seconds) for establishing TCP connection to target website. Affects all requests. _Default: 20 seconds._

## License
Licensed under the [Apache License](LICENSE)

Initial version of this plugin was developed by Google.

Disclaimer: This is not an official Google product.
