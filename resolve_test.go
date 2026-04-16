package forwardproxy

import "testing"

func TestMatchHostPort(t *testing.T) {
	tests := []struct {
		pattern  string
		hostPort string
		want     bool
	}{
		// Exact match
		{"example.com:443", "example.com:443", true},
		{"example.com:443", "other.com:443", false},
		{"example.com:443", "example.com:80", false},

		// Wildcard match
		{"*.example.com:443", "sub.example.com:443", true},
		{"*.example.com:443", "deep.sub.example.com:443", true},
		{"*.example.com:443", "example.com:443", false},
		{"*.example.com:443", "sub.example.com:80", false},
		{"*.example.com:443", "sub.other.com:443", false},

		// Wildcard with different ports
		{"*.something.test:443", "test.something.test:443", true},
		{"*.something.test:443", "fleet.something.test:443", true},
		{"*.something.test:443", "test.something.test:80", false},

		// No wildcard, no match
		{"example.com:443", "sub.example.com:443", false},
	}

	for _, tt := range tests {
		got := matchHostPort(tt.pattern, tt.hostPort)
		if got != tt.want {
			t.Errorf("matchHostPort(%q, %q) = %v, want %v", tt.pattern, tt.hostPort, got, tt.want)
		}
	}
}

func TestResolveAddress(t *testing.T) {
	h := Handler{
		Resolve: []ResolveEntry{
			{From: "*.something.test:443", To: "127.0.0.1:443"},
			{From: "specific.host:8080", To: "10.0.0.1:8080"},
		},
	}

	tests := []struct {
		input string
		want  string
	}{
		// Wildcard match
		{"test.something.test:443", "127.0.0.1:443"},
		{"fleet.something.test:443", "127.0.0.1:443"},

		// Exact match
		{"specific.host:8080", "10.0.0.1:8080"},

		// No match — returned as-is
		{"other.com:443", "other.com:443"},
		{"test.something.test:80", "test.something.test:80"},
	}

	for _, tt := range tests {
		got := h.resolveAddress(tt.input)
		if got != tt.want {
			t.Errorf("resolveAddress(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
