package pkg

import (
	"net/http"
	"strings"
)

func GenerateFingerprint(r *http.Request) string {
	ua := r.UserAgent()

	if xfHeader := r.Header.Get("X-Forwarded-For"); xfHeader != "" {
		ips := strings.TrimSpace(strings.SplitN(xfHeader, ",", 2)[0])
		return ips + ua
	}

	ips := r.RemoteAddr
	if idx := strings.Index(ips, ":"); idx != -1 {
		return ips[:idx]
	}

	return ips + ua
}
