package main

import (
	"github.com/caddyserver/caddy/caddy/caddymain"

	_ "github.com/caddyserver/forwardproxy"
)

func main() {
	caddymain.EnableTelemetry = false
	caddymain.Run()
}
