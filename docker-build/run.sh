#!/usr/bin/env bash

print_help() {
  cat <<EOF
  All arguments to this script are passed to docker.
  One can configure docker image by setting variables and mounting folders.

  To set address of served website:
    -e SITE_ADDRESS=(string)

  To set up credentials for your forwardproxy:
    -e PROXY_USERNAME=(string) -e PROXY_PASSWORD=(string)

  To enable probing resistance, and specify (optional) secret link:
    -e PROBE_RESISTANT=true -e SECRET_LINK=(string)

  To manually provide Caddyfile(and ignore all of above):
    -v (path to Caddyfile):/etc/caddy/Caddyfile

  To set served files:
    -v (path to files):/srv/index

  To persistently save certificates and avoid LE issuance limit:
    -v (path to some storage folder):/root/.caddy

  One can pass options to caddy using CADDY_OPTS e.g.:
    -e CADDY_OPTS="-ca https://acme-staging.api.letsencrypt.org/directory"

  One can also directly pass here other useful docker commands, e.g.:
    --restart always
EOF
}

if [[ $1 == "help" || $1 == "--help" || $1 == "-h" ]]; then
    print_help
    exit 0
fi

docker run -p 2015:2015 -p 443:443 -p 80:80 "$@" caddy-forwardproxy
