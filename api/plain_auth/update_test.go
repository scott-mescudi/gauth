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
	"github.com/scott-mescudi/gauth/middlewares"
	"github.com/scott-mescudi/gauth/shared/auth"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestUpdatePassword(t *testing.T) {
	dsn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	pool, err := database.ConnectToDatabase("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := au.HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	st := &PlainAuthAPI{AuthCore: &au.Coreplainauth{DB: pool, AccessTokenExpiration: 1 * time.Hour, RefreshTokenExpiration: 1 * time.Hour}}

	rec := httptest.NewRecorder()
	body, err := json.Marshal(loginRequest{Identifier: "jack", Password: "hey"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	st.Login(rec, req)

	var info loginResponse
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		oldPassword  string
		newPassword  string
		expectedCode int
	}{
		{
			name:         "Valid Change",
			oldPassword:  "hey",
			newPassword:  "hey2",
			expectedCode: http.StatusOK,
		},
	}

	s := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	x := &middlewares.MiddlewareConfig{JWTConfig: s}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body, err := json.Marshal(updatePasswordRequest{OldPassword: tt.oldPassword, NewPassword: tt.newPassword})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/update/password", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", info.AccessToken)

			handler := x.AuthMiddleware(http.HandlerFunc(st.UpdatePassword))
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				fmt.Println(rec.Body)
				t.Fatalf("got %v expected %v\n", rec.Code, tt.expectedCode)
			}
		})
	}
}

func TestUpdateUsername(t *testing.T) {
	dsn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	pool, err := database.ConnectToDatabase("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := au.HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	st := &PlainAuthAPI{AuthCore: &au.Coreplainauth{DB: pool, AccessTokenExpiration: 1 * time.Hour, RefreshTokenExpiration: 1 * time.Hour}}

	rec := httptest.NewRecorder()
	body, err := json.Marshal(loginRequest{Identifier: "jack", Password: "hey"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	st.Login(rec, req)

	var info loginResponse
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		newUsername  string
		expectedCode int
	}{
		{
			name:         "Valid Change",
			newUsername:  "jack32",
			expectedCode: http.StatusOK,
		},
	}

	s := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	x := &middlewares.MiddlewareConfig{JWTConfig: s}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body, err := json.Marshal(updateUsernameRequest{NewUsername: tt.newUsername})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/update/username", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", info.AccessToken)

			handler := x.AuthMiddleware(http.HandlerFunc(st.UpdateUsername))
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				fmt.Println(rec.Body)
				t.Fatalf("got %v expected %v\n", rec.Code, tt.expectedCode)
			}
		})
	}
}

func TestUpdateEmail(t *testing.T) {
	dsn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	pool, err := database.ConnectToDatabase("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := au.HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "jack2", "jack3@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	st := &PlainAuthAPI{AuthCore: &au.Coreplainauth{DB: pool, AccessTokenExpiration: 1 * time.Hour, RefreshTokenExpiration: 1 * time.Hour}}

	rec := httptest.NewRecorder()
	body, err := json.Marshal(loginRequest{Identifier: "jack", Password: "hey"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	st.Login(rec, req)

	var info loginResponse
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		newEmail     string
		expectedCode int
	}{
		{
			name:         "Valid Change",
			newEmail:     "jack2@jack.com",
			expectedCode: http.StatusOK,
		},
		{
			name:         "Invalid Change (Invalid Email Format)",
			newEmail:     "jack2jack.com",
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "Email Already Taken",
			newEmail:     "jack3@jack.com",
			expectedCode: http.StatusConflict,
		},
		{
			name:         "Empty Email Field",
			newEmail:     "",
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "Change to Same Email",
			newEmail:     "jack2@jack.com", // Email is the same as before
			expectedCode: http.StatusConflict,
		},
		{
			name:         "Valid Change with Complex Email",
			newEmail:     "jack.jack2+test@jack.com", // Complex email with plus sign
			expectedCode: http.StatusOK,
		},
	}

	s := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	x := &middlewares.MiddlewareConfig{JWTConfig: s}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body, err := json.Marshal(updateEmailRequest{NewEmail: tt.newEmail})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/update/email", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", info.AccessToken)

			handler := x.AuthMiddleware(http.HandlerFunc(st.UpdateEmail))
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				fmt.Println(rec.Body)
				t.Fatalf("got %v expected %v\n", rec.Code, tt.expectedCode)
			}
		})
	}
}
