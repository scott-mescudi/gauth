package coreplainauth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/auth"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
	"github.com/scott-mescudi/gauth/shared/variables"
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

	ph, err := HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	_, err = pool.AddUser(t.Context(), "jack1", "jack1@jack.com", "user", ph)
	if err != nil {
		t.Fatal(err)
	}

	pa := &Coreplainauth{DB: pool, AccessTokenExpiration: 1 * time.Hour, RefreshTokenExpiration: 48 * time.Hour}

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
			expectedErr: errs.ErrUnknownRole,
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
			at, rt, err := pa.SignupHandler(tt.username, tt.email, tt.password, tt.role)
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Expected %v got %v", tt.expectedErr, err)
			}

			if err == nil {
				_, typet, err := auth.ValidateHmac(at)
				if err != nil || typet != variables.ACCESS_TOKEN {
					t.Error("Got invalid access token")
				}

				_, typet, err = auth.ValidateHmac(rt)
				if err != nil || typet != variables.REFRESH_TOKEN {
					t.Error("Got invalid refresh token")
				}
			}
		})
	}
}
