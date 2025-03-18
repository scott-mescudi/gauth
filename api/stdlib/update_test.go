package plainauth

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	au "github.com/scott-mescudi/gauth/core"
	"github.com/scott-mescudi/gauth/database"
	middlewares "github.com/scott-mescudi/gauth/middlewares/auth"

	"github.com/scott-mescudi/gauth/pkg/auth"
	tu "github.com/scott-mescudi/gauth/pkg/testutils"
)

func TestUpdateEmail(t *testing.T) {
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

	err = pa.SignupHandler(t.Context(), "", "", "jack", "jack@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	err = pa.SignupHandler(t.Context(), "", "", "jill", "jill@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	at, _, err := pa.LoginHandler(t.Context(), "jack", "hey", "")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		body         *updateEmailRequest
		token        string
		expectedCode int
	}{
		{
			name: "Valid update email",
			body: &updateEmailRequest{
				NewEmail: "jack2@jack.com",
			},
			token:        at,
			expectedCode: 200,
		},
		{
			name: "Invalid email format",
			body: &updateEmailRequest{
				NewEmail: "invalid-email",
			},
			token:        at,
			expectedCode: 400,
		},
		{
			name: "Email already in use",
			body: &updateEmailRequest{
				NewEmail: "jill@jack.com",
			},
			token:        at,
			expectedCode: 409,
		},
		{
			name: "Unauthorized request (no token)",
			body: &updateEmailRequest{
				NewEmail: "jack3@jack.com",
			},
			token:        "",
			expectedCode: http.StatusForbidden,
		},
		{
			name: "Invalid token",
			body: &updateEmailRequest{
				NewEmail: "jack4@jack.com",
			},
			token:        "invalid.token.here",
			expectedCode: http.StatusForbidden,
		},
		{
			name: "Empty email field",
			body: &updateEmailRequest{
				NewEmail: "",
			},
			token:        at,
			expectedCode: 400,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest("POST", "/update/email", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", tt.token)

			z := &middlewares.MiddlewareConfig{JWTConfig: x}

			handler := z.AuthMiddleware(http.HandlerFunc(af.UpdateEmail))
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				fmt.Println(rec.Body)
				t.Errorf("Got %v, Expected %v", rec.Code, tt.expectedCode)
			}
		})
	}
}

func TestUpdatePassword(t *testing.T) {
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

	err = pa.SignupHandler(t.Context(), "", "", "jack", "jack@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	err = pa.SignupHandler(t.Context(), "", "", "jill", "jill@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	at, _, err := pa.LoginHandler(t.Context(), "jack", "hey", "")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		body         *updatePasswordRequest
		token        string
		expectedCode int
	}{
		{
			name: "Valid update password",
			body: &updatePasswordRequest{
				OldPassword: "hey",
				NewPassword: "hey2",
			},
			token:        at,
			expectedCode: 200,
		},
		{
			name: "Incorrect old password",
			body: &updatePasswordRequest{
				OldPassword: "wrongpassword",
				NewPassword: "newpassword123",
			},
			token:        at,
			expectedCode: 400,
		},
		{
			name: "Same old and new password",
			body: &updatePasswordRequest{
				OldPassword: "hey",
				NewPassword: "hey",
			},
			token:        at,
			expectedCode: 400,
		},
		{
			name: "Unauthorized request (no token)",
			body: &updatePasswordRequest{
				OldPassword: "hey",
				NewPassword: "newpassword123",
			},
			token:        "",
			expectedCode: http.StatusForbidden,
		},
		{
			name: "Invalid token",
			body: &updatePasswordRequest{
				OldPassword: "hey",
				NewPassword: "newpassword123",
			},
			token:        "invalid.token.here",
			expectedCode: http.StatusForbidden,
		},
		{
			name: "Empty old password",
			body: &updatePasswordRequest{
				OldPassword: "",
				NewPassword: "newpassword123",
			},
			token:        at,
			expectedCode: 400,
		},
		{
			name: "Empty new password",
			body: &updatePasswordRequest{
				OldPassword: "hey",
				NewPassword: "",
			},
			token:        at,
			expectedCode: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest("POST", "/update/email", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", tt.token)

			z := &middlewares.MiddlewareConfig{JWTConfig: x}

			handler := z.AuthMiddleware(http.HandlerFunc(af.UpdatePassword))
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				fmt.Println(rec.Body)
				t.Errorf("Got %v, Expected %v", rec.Code, tt.expectedCode)
			}
		})
	}
}

func TestUpdateUsername(t *testing.T) {
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

	err = pa.SignupHandler(t.Context(), "", "", "jack", "jack@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	err = pa.SignupHandler(t.Context(), "", "", "jill", "jill@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	at, _, err := pa.LoginHandler(t.Context(), "jack", "hey", "")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		body         *updateUsernameRequest
		token        string
		expectedCode int
	}{
		{
			name: "Valid update username",
			body: &updateUsernameRequest{
				NewUsername: "jack2",
			},
			token:        at,
			expectedCode: 200,
		},
		{
			name: "Username already taken",
			body: &updateUsernameRequest{
				NewUsername: "jill",
			},
			token:        at,
			expectedCode: 409,
		},
		{
			name: "Invalid username format",
			body: &updateUsernameRequest{
				NewUsername: "jack@123", // Assuming special characters are not allowed
			},
			token:        at,
			expectedCode: 400,
		},
		{
			name: "Unauthorized request (no token)",
			body: &updateUsernameRequest{
				NewUsername: "jack3",
			},
			token:        "",
			expectedCode: http.StatusForbidden,
		},
		{
			name: "Invalid token",
			body: &updateUsernameRequest{
				NewUsername: "jack4",
			},
			token:        "invalid.token.here",
			expectedCode: http.StatusForbidden,
		},
		{
			name: "Empty username",
			body: &updateUsernameRequest{
				NewUsername: "",
			},
			token:        at,
			expectedCode: 400,
		},
		{
			name: "Too long username",
			body: &updateUsernameRequest{
				NewUsername: string(make([]byte, 394)),
			},
			token:        at,
			expectedCode: 400,
		},
		{
			name: "Username with special characters",
			body: &updateUsernameRequest{
				NewUsername: "jack$%^&@",
			},
			token:        at,
			expectedCode: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest("POST", "/update/email", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", tt.token)

			z := &middlewares.MiddlewareConfig{JWTConfig: x}

			handler := z.AuthMiddleware(http.HandlerFunc(af.UpdateUsername))
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				fmt.Println(rec.Body)
				t.Errorf("Got %v, Expected %v", rec.Code, tt.expectedCode)
			}
		})
	}
}
