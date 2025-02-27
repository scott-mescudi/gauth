package plainauth

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	coreplainauth "github.com/scott-mescudi/gauth/core/plain_auth"
	"github.com/scott-mescudi/gauth/database"
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

	af := &PlainAuthAPI{AuthCore: &coreplainauth.Coreplainauth{DB: db}}

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
			expectedCode: http.StatusOK,
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
			name:        "valid register with uppercase email",
			contentType: "application/json",
			body: signupRequest{
				Username: "jake",
				Email:    "JACK@jack.com",
				Password: "scott",
				Role:     "user",
			},
			expectedCode: http.StatusOK,
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
