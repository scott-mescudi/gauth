package middlewares

import (
	"net/http"

	auth "github.com/scott-mescudi/gauth/shared/auth"
	"github.com/scott-mescudi/gauth/shared/variables"
)

func AuthMiddleware(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		userID, tokenType, err := auth.ValidateHmac(token)
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
