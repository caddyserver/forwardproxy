FROM golang:1.14.15 AS builder
RUN git clone https://github.com/caddyserver/forwardproxy.git
WORKDIR /go/forwardproxy/cmd/caddy 
RUN go build caddy.go

FROM ubuntu:20.04
COPY --from=builder /go/forwardproxy/cmd/caddy/caddy /usr/bin/caddy
EXPOSE 80 443
ENTRYPOINT ["/usr/bin/caddy"] 
CMD ["-conf", "/etc/caddy/Caddyfile", "--log", "/dev/stdout", "--agree=true"]