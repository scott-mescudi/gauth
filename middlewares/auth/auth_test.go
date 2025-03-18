package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	auth "github.com/scott-mescudi/gauth/pkg/auth"
	"github.com/scott-mescudi/gauth/pkg/variables"
)

func TestAuthMiddleware(t *testing.T) {
	s := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}

	j := &MiddlewareConfig{JWTConfig: s}

	uid := uuid.New()
	tests := []struct {
		name       string
		token      string
		setupAuth  func() (string, error)
		expectCode int
		userID     string
	}{
		{
			name: "Valid Token",
			setupAuth: func() (string, error) {
				return s.GenerateHMac(uid, variables.ACCESS_TOKEN, time.Now().Add(2*time.Minute))
			},
			expectCode: http.StatusOK,
			userID:     uid.String(),
		},
		{
			name:       "Missing Token",
			token:      "",
			expectCode: http.StatusForbidden,
		},
		{
			name: "Invalid Token",
			setupAuth: func() (string, error) {
				return "invalid.token.string", nil
			},
			expectCode: http.StatusForbidden,
		},
		{
			name: "Wrong Token Type",
			setupAuth: func() (string, error) {
				return s.GenerateHMac(uuid.New(), variables.REFRESH_TOKEN, time.Now().Add(2*time.Minute))
			},
			expectCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token string
			if tt.setupAuth != nil {
				token, _ = tt.setupAuth()
			} else {
				token = tt.token
			}

			req := httptest.NewRequest("GET", "/", nil)
			if token != "" {
				req.Header.Set("Authorization", token)
			}

			rw := httptest.NewRecorder()
			handler := j.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			handler.ServeHTTP(rw, req)

			if rw.Code != tt.expectCode {
				t.Error("Codes dont match")
			}

			if tt.expectCode == http.StatusOK {
				if tt.userID != req.Header.Get("X-GAUTH-USERID") {
					t.Errorf("Expected userID %v but got %s", tt.userID, req.Header.Get("X-USERID"))
				}
			}
		})
	}
}
