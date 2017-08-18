#!/usr/bin/env bash

CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"
ROOTDIR="${ROOTDIR:-/srv/index}"
SITE_ADDRESS="${SITE_ADDRESS:-localhost}"

generate_caddyfile() {
    mkdir -p "$(dirname "${CADDYFILE}")"

    echo "${SITE_ADDRESS} {" > ${CADDYFILE}
    echo "  root $ROOTDIR" >> ${CADDYFILE}

    echo "  forwardproxy {" >> ${CADDYFILE}
    if [[ ! -z ${PROXY_USERNAME} ]]; then
        echo "    basicauth ${PROXY_USERNAME} ${PROXY_PASSWORD}" >> ${CADDYFILE}
    fi
    if [[ "${PROBE_RESISTANT}" = true ]]; then
        echo "    probe_resistance ${SECRET_LINK}" >> ${CADDYFILE}
    fi
    echo "  }" >> ${CADDYFILE}

    echo "}" >> ${CADDYFILE}
}

if [ -f "${CADDYFILE}" ]; then
    echo "Using provided Caddyfile"
else
    echo "Caddyfile is not provided: generating new one"
    generate_caddyfile
fi

caddy ${CADDY_OPTS} -conf ${CADDYFILE}
