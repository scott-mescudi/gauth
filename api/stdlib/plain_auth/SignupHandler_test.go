package plainauth

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	au "github.com/scott-mescudi/gauth/core/plain_auth"
	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/auth"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestSignup(t *testing.T) {
	connstr, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db, err := database.ConnectToDatabase("postgres", connstr)
	if err != nil {
		t.Fatal(err)
	}

	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &au.Coreplainauth{
		DB:                     db,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
	}


	af := &PlainAuthAPI{AuthCore: pa}

	tests := []struct {
		name         string
		contentType  string
		body         signupRequest
		expectedCode int
	}{
		{
			name:        "valid register",
			contentType: "application/json",
			body: signupRequest{
				Username: "jack",
				Email:    "jack@jack.com",
				Password: "scott",
				Role:     "user",
			},
			expectedCode: http.StatusCreated,
		},
		{
			name:        "missing username",
			contentType: "application/json",
			body: signupRequest{
				Email:    "jack@jack.com",
				Password: "scott",
				Role:     "user",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:        "missing email",
			contentType: "application/json",
			body: signupRequest{
				Username: "jack",
				Password: "scott",
				Role:     "user",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:        "missing password",
			contentType: "application/json",
			body: signupRequest{
				Username: "jack",
				Email:    "jack@jack.com",
				Role:     "user",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:        "missing role",
			contentType: "application/json",
			body: signupRequest{
				Username: "jack",
				Email:    "jack@jack.com",
				Password: "scott",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:        "invalid email format",
			contentType: "application/json",
			body: signupRequest{
				Username: "jack",
				Email:    "jackjack.com",
				Password: "scott",
				Role:     "user",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:        "role not recognized",
			contentType: "application/json",
			body: signupRequest{
				Username: "jack",
				Email:    "jack@jack.com",
				Password: "scott",
				Role:     "kajhdfjhb",
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:        "duplicate username",
			contentType: "application/json",
			body: signupRequest{
				Username: "jack",
				Email:    "jack@jack.com",
				Password: "scott",
				Role:     "user",
			},
			expectedCode: http.StatusConflict,
		},
		{
			name:        "duplicate email",
			contentType: "application/json",
			body: signupRequest{
				Username: "john",
				Email:    "jack@jack.com",
				Password: "scott",
				Role:     "user",
			},
			expectedCode: http.StatusConflict,
		},
		{
			name:        "invalid content type",
			contentType: "text/plain",
			body: signupRequest{
				Username: "jack",
				Email:    "jack@jack.com",
				Password: "scott",
				Role:     "user",
			},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Error("Failed to marsha json")
			}

			req := httptest.NewRequest("POST", "/signup", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", tt.contentType)

			af.Signup(rec, req)
			if rec.Code != tt.expectedCode {
				fmt.Println(rec.Body)
				t.Errorf("Got %v Expected %v", rec.Code, tt.expectedCode)
			}
		})
	}
}
