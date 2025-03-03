package plainauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	au "github.com/scott-mescudi/gauth/core/plain_auth"
	"github.com/scott-mescudi/gauth/database"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestLogin(t *testing.T) {
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

	tests := []struct {
		name           string
		identifier     string
		password       string
		contentType    string
		expectedStatus int
	}{
		{
			name:           "valid username login",
			identifier:     "jack",
			password:       "hey",
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "valid email login",
			identifier:     "jack@jack.com",
			password:       "hey",
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid content type",
			identifier:     "jack@jack.com",
			password:       "hey",
			contentType:    "text/plain",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid username login",
			identifier:     "jack",
			password:       "wrongpass",
			contentType:    "application/json",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid email login",
			identifier:     "jack@jack.com",
			password:       "wrongpass",
			contentType:    "application/json",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "missing password",
			identifier:     "jack@jack.com",
			password:       "",
			contentType:    "application/json",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid JSON body",
			identifier:     "",
			password:       "",
			contentType:    "application/json",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "successful login with refresh token",
			identifier:     "jack@jack.com",
			password:       "hey",
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body, err := json.Marshal(loginRequest{Identifier: tt.identifier, Password: tt.password})
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", tt.contentType)

			st.Login(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Got %v Expected %v\n", rec.Code, tt.expectedStatus)
			}
		})
	}
}

func BenchmarkLoginSpeed(b *testing.B) {
	dsn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		b.Fatal(err)
	}
	defer clean()

	pool, err := database.ConnectToDatabase("postgres", dsn)
	if err != nil {
		b.Fatal(err)
	}

	ph, err := au.HashPassword("hey")
	if err != nil {
		b.Fatal(err)
	}

	_, err = pool.AddUser(b.Context(), "", "", "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		b.Fatal(err)
	}

	st := &PlainAuthAPI{AuthCore: &au.Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 1 * time.Hour,
	}}

	body, err := json.Marshal(loginRequest{Identifier: "jack@jack.com", Password: "hey"})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		st.Login(rec, req)
		rec.Result()
		b.StopTimer()
	}
}
