package forwardproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// TestUnixSOCKSUpstream is the #677 regression for Avon's emitted upstream URI.
// A real Unix listener receives the unresolvable target as a SOCKS5 domain name.
func TestUnixSOCKSUpstream(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "socks.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err != nil {
			result <- err
			return
		}
		if string(greeting) != "\x05\x01\x00" {
			result <- &net.AddrError{Err: "unexpected SOCKS greeting", Addr: string(greeting)}
			return
		}
		if _, err = conn.Write([]byte{5, 0}); err != nil {
			result <- err
			return
		}
		header := make([]byte, 5)
		if _, err = io.ReadFull(conn, header); err != nil {
			result <- err
			return
		}
		address := make([]byte, int(header[4])+2)
		if _, err = io.ReadFull(conn, address); err != nil {
			result <- err
			return
		}
		if string(header[:4]) != "\x05\x01\x00\x03" || string(address[:len(address)-2]) != "unresolvable.onion" || binary.BigEndian.Uint16(address[len(address)-2:]) != 443 {
			result <- &net.AddrError{Err: "unexpected SOCKS target", Addr: string(address)}
			return
		}
		_, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		if err == nil {
			_, err = io.CopyN(conn, conn, 4)
		}
		result <- err
	}()
	h := &Handler{Upstream: "socks5://unix:/" + socket}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.httpTransport.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := h.dialContext(ctx, "tcp", "unresolvable.onion:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil || string(response) != "ping" {
		t.Fatalf("tunnel response %q: %v", response, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestUnixSOCKSUpstreamInvalid(t *testing.T) {
	for _, upstream := range []string{
		"socks5://unix://", "socks5://unix:/relative",
		"socks5://unix://tmp/socks?query", "socks5://unix://tmp/socks#fragment",
		"socks5://user:password@unix://tmp/socks",
	} {
		t.Run(upstream, func(t *testing.T) {
			h := &Handler{Upstream: upstream, DisableInsecureUpstreamsCheck: true}
			if err := h.Provision(caddy.Context{Context: context.Background()}); err == nil {
				t.Fatal("invalid Unix SOCKS upstream must fail provisioning")
			}
		})
	}
}

func TestUnixSOCKSUpstreamUnavailable(t *testing.T) {
	h := &Handler{Upstream: "socks5://unix:/" + filepath.Join(t.TempDir(), "missing.sock"), DisableInsecureUpstreamsCheck: true}
	if err := h.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	defer h.httpTransport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := h.dialContext(ctx, "tcp", "unresolvable.onion:443")
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("missing SOCKS socket must fail closed")
	}
}
