package plainauth

import (
	"net/http"
	"strings"
)

func GetFingerprint(r *http.Request) *Fingerprint {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return nil
	}

	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	userAgent := r.UserAgent()

	response := Fingerprint{
		IP:        ip,
		UserAgent: userAgent,
	}

	return &response
}
