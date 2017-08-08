FROM alpine:3.6

LABEL description="Docker image for caddy+forwardproxy plugin."
LABEL maintainer="SergeyFrolov@colorado.edu"

RUN apk add --no-cache ca-certificates bash curl

RUN curl --fail https://getcaddy.com | bash -s http.forwardproxy

COPY gen_caddyfile_and_start.sh /bin/

VOLUME /root/.caddy

EXPOSE 80 443 2015

ENTRYPOINT /bin/gen_caddyfile_and_start.sh
