package coreplainauth

import (
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/auth"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/hashing"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestUpdateEmail(t *testing.T) {
	str, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}

	defer clean()

	pool, err := database.ConnectToDatabase("postgres", str)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := hashing.HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	uid, err := pool.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "skibsd", "alreadyused@example.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
	}

	tests := []struct {
		name          string
		email         string
		expectedError error
	}{
		{
			name:          "Invalid email - empty",
			email:         "",
			expectedError: errs.ErrInvalidEmail,
		},
		{
			name:          "Invalid email - too long",
			email:         string(make([]byte, 255)) + "@example.com",
			expectedError: errs.ErrEmailTooLong,
		},
		{
			name:          "Invalid email - regex mismatch",
			email:         "invalidemail",
			expectedError: errs.ErrInvalidEmail,
		},
		{
			name:          "Valid email - successful update",
			email:         "validemail@example.com",
			expectedError: nil,
		},
		{
			name:          "Email already the same",
			email:         "validemail@example.com",
			expectedError: errs.ErrNoChange,
		},
		{
			name:          "Email already in use",
			email:         "alreadyused@example.com",
			expectedError: errs.ErrDuplicateKey,
		},
		{
			name:          "Email with leading/trailing spaces",
			email:         "   user@example.com   ",
			expectedError: errs.ErrInvalidEmail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pa.UpdateEmail(t.Context(), uid, tt.email)
			if err != tt.expectedError {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}

func TestUpdateUsername(t *testing.T) {
	str, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}

	defer clean()

	pool, err := database.ConnectToDatabase("postgres", str)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := hashing.HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	uid, err := pool.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "jay", "alreadyused@example.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
	}

	tests := []struct {
		name          string
		username      string
		expectedError error
	}{
		{
			name:          "Invalid username - empty",
			username:      "",
			expectedError: errs.ErrInvalidUsername,
		},
		{
			name:          "Invalid username - too long",
			username:      string(make([]byte, 255)),
			expectedError: errs.ErrUsernameTooLong,
		},
		{
			name:          "Valid username - successful update",
			username:      "validusername",
			expectedError: nil,
		},
		{
			name:          "Username already the same",
			username:      "validusername",
			expectedError: errs.ErrNoChange,
		},
		{
			name:          "Username already in use",
			username:      "jay",
			expectedError: errs.ErrDuplicateKey,
		},
		{
			name:          "Username with leading/trailing spaces",
			username:      "   user   ",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pa.UpdateUsername(t.Context(), uid, tt.username)
			if err != tt.expectedError {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}

func TestUpdatePassword(t *testing.T) {
	str, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}

	defer clean()

	pool, err := database.ConnectToDatabase("postgres", str)
	if err != nil {
		t.Fatal(err)
	}
	oldPassword := "oldPassword123"
	hash, err := hashing.HashPassword(oldPassword)
	if err != nil {
		t.Fatal(err)
	}

	uid, err := pool.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "jay", "alreadyused@example.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
	}

	tests := []struct {
		name        string
		oldPassword string
		newPassword string
		expectedErr error
	}{
		{
			name:        "valid change",
			oldPassword: oldPassword,
			newPassword: "hey",
			expectedErr: nil,
		},
		{
			name:        "empty",
			oldPassword: "",
			newPassword: "",
			expectedErr: errs.ErrEmptyCredentials,
		},
		{
			name:        "too long opass",
			oldPassword: string(make([]byte, 400)),
			newPassword: "",
			expectedErr: errs.ErrEmptyCredentials,
		},
		{
			name:        "too long npass",
			oldPassword: "",
			newPassword: string(make([]byte, 400)),
			expectedErr: errs.ErrEmptyCredentials,
		},
		{
			name:        "invalid oldpass",
			oldPassword: "skduj",
			newPassword: "lwdif",
			expectedErr: errs.ErrIncorrectPassword,
		},
		{
			name:        "no change",
			oldPassword: "hey",
			newPassword: "hey",
			expectedErr: errs.ErrNoChange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pa.UpdatePassword(t.Context(), uid, tt.oldPassword, tt.newPassword)
			if err != tt.expectedErr {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}
