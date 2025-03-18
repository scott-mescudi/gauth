package coreplainauth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/pkg/auth"
	"github.com/scott-mescudi/gauth/pkg/email"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
	"github.com/scott-mescudi/gauth/pkg/hashing"
	tu "github.com/scott-mescudi/gauth/pkg/testutils"
)

func TestSignup(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}

	defer clean()

	pool, err := database.ConnectToDatabase("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := hashing.HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "jack1", "jack1@jack.com", "user", ph, true)
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
		username    string
		email       string
		password    string
		role        string
		expectedErr error
	}{
		{
			name:        "valid user signup",
			username:    "jack2",
			email:       "jack2@jack.com",
			password:    "securepassword123",
			role:        "user",
			expectedErr: nil,
		},
		{
			name:        "valid moderator signup",
			username:    "moderator2",
			email:       "mod2@example.com",
			password:    "ModPass123!",
			role:        "moderator",
			expectedErr: nil,
		},
		{
			name:        "valid guest signup",
			username:    "guest456",
			email:       "guest456@site.com",
			password:    "guestPass!",
			role:        "guest",
			expectedErr: nil,
		},
		{
			name:        "empty username",
			username:    "",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidUsername,
		},
		{
			name:        "username contains @",
			username:    "jack@email",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidUsername,
		},
		{
			name:        "empty email",
			username:    "jack",
			email:       "",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidEmail,
		},
		{
			name:        "invalid email format",
			username:    "jack",
			email:       "invalid-email",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidEmail,
		},
		{
			name:        "empty password",
			username:    "jack",
			email:       "jack@jack.com",
			password:    "",
			role:        "user",
			expectedErr: errs.ErrEmptyCredentials,
		},
		{
			name:        "password too long",
			username:    "jack",
			email:       "jack@jack.com",
			password:    strings.Repeat("a", 255),
			role:        "user",
			expectedErr: errs.ErrPasswordTooLong,
		},
		{
			name:        "empty role",
			username:    "jack",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "",
			expectedErr: errs.ErrEmptyCredentials,
		},
		{
			name:        "invalid role",
			username:    "jack",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "superuser",
			expectedErr: errs.ErrUnknownRole,
		},
		{
			name:        "SQL injection attempt",
			username:    "jack",
			email:       "' OR '1'='1'; --",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidEmail,
		},
		{
			name:        "special characters in username",
			username:    "jack@123",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidUsername,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pa.SignupHandler(t.Context(), "", "", tt.username, tt.email, tt.password, tt.role, false)
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Expected %v got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestVerifiedSignup(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}

	defer clean()

	pool, err := database.ConnectToDatabase("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := hashing.HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "jack1", "jack1@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	bldr := strings.Builder{}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		EmailProvider:          &email.MockClient{Writer: &bldr},
		EmailTemplateConfig: &EmailTemplateConfig{
			SignupTemplate:         "",
			UpdatePasswordTemplate: "",
			UpdateEmailTemplate:    "",
		},
	}

	tests := []struct {
		name        string
		username    string
		email       string
		password    string
		role        string
		expectedErr error
	}{
		{
			name:        "valid user signup",
			username:    "jack2",
			email:       "jack2@jack.com",
			password:    "securepassword123",
			role:        "user",
			expectedErr: nil,
		},
		{
			name:        "valid moderator signup",
			username:    "moderator2",
			email:       "mod2@example.com",
			password:    "ModPass123!",
			role:        "moderator",
			expectedErr: nil,
		},
		{
			name:        "valid guest signup",
			username:    "guest456",
			email:       "guest456@site.com",
			password:    "guestPass!",
			role:        "guest",
			expectedErr: nil,
		},
		{
			name:        "empty username",
			username:    "",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidUsername,
		},
		{
			name:        "username contains @",
			username:    "jack@email",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidUsername,
		},
		{
			name:        "empty email",
			username:    "jack",
			email:       "",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidEmail,
		},
		{
			name:        "invalid email format",
			username:    "jack",
			email:       "invalid-email",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidEmail,
		},
		{
			name:        "empty password",
			username:    "jack",
			email:       "jack@jack.com",
			password:    "",
			role:        "user",
			expectedErr: errs.ErrEmptyCredentials,
		},
		{
			name:        "password too long",
			username:    "jack",
			email:       "jack@jack.com",
			password:    strings.Repeat("a", 255),
			role:        "user",
			expectedErr: errs.ErrPasswordTooLong,
		},
		{
			name:        "empty role",
			username:    "jack",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "",
			expectedErr: errs.ErrEmptyCredentials,
		},
		{
			name:        "invalid role",
			username:    "jack",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "superuser",
			expectedErr: errs.ErrUnknownRole,
		},
		{
			name:        "SQL injection attempt",
			username:    "jack",
			email:       "' OR '1'='1'; --",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidEmail,
		},
		{
			name:        "special characters in username",
			username:    "jack@123",
			email:       "jack@jack.com",
			password:    "password123",
			role:        "user",
			expectedErr: errs.ErrInvalidUsername,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pa.SignupHandler(t.Context(), "", "", tt.username, tt.email, tt.password, tt.role, true)
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Expected %v got %v", tt.expectedErr, err)
			}
			time.Sleep(1 * time.Second)
			if tt.expectedErr == nil {
				if bldr.String() == "" {
					t.Fatal("Failed to return token")
				}
			}

			bldr.Reset()
		})
	}

}

func TestVerifySignup(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}

	defer clean()

	pool, err := database.ConnectToDatabase("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := hashing.HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "", "", "jack1", "jack1@jack.com", "user", ph, false)
	if err != nil {
		t.Fatal(err)
	}

	bldr := strings.Builder{}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		EmailProvider:          &email.MockClient{Writer: &bldr},
		EmailTemplateConfig: &EmailTemplateConfig{
			SignupTemplate:         "",
			UpdatePasswordTemplate: "",
			UpdateEmailTemplate:    "",
		},
	}

	err = pa.SignupHandler(t.Context(), "", "", "jack", "jack@jack.com", "hey", "admin", true)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1 * time.Second)
	err = pa.VerifySignupToken(t.Context(), bldr.String())
	if err != nil {
		t.Fatal(err)
	}
}
