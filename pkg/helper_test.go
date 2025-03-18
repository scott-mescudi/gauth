package pkg

import (
	"net/http/httptest"
	"testing"
)

func TestGenerateFingerprint(t *testing.T) {
	tests := []struct {
		remoteAddr string
		ua         string
		xfHeader   string
		expected   string
	}{
		{"192.168.1.1:8080", "Mozilla/5.0", "", "192.168.1.1"},
		{"", "Mozilla/5.0", "127.0.0.1, 192.168.1.2", "127.0.0.1Mozilla/5.0"},
		{"192.168.1.1:8080", "Mozilla/5.0", "10.0.0.1", "10.0.0.1Mozilla/5.0"},
	}

	for _, test := range tests {
		t.Run(test.ua, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("User-Agent", test.ua)
			req.RemoteAddr = test.remoteAddr
			if test.xfHeader != "" {
				req.Header.Set("X-Forwarded-For", test.xfHeader)
			}

			fingerprint := GenerateFingerprint(req)

			if fingerprint != test.expected {
				t.Errorf("expected fingerprint %s, got %s", test.expected, fingerprint)
			}
		})
	}
}
