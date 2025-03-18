package middlewares

import (
	"net/http"

	auth "github.com/scott-mescudi/gauth/pkg/auth"
	"github.com/scott-mescudi/gauth/pkg/variables"
)

type MiddlewareConfig struct {
	JWTConfig *auth.JWTConfig
}

func (s *MiddlewareConfig) AuthMiddleware(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		userID, tokenType, err := s.JWTConfig.ValidateHmac(token)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if tokenType != variables.ACCESS_TOKEN {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		r.Header.Add("X-GAUTH-USERID", userID.String())
		next.ServeHTTP(w, r)
	})
}
