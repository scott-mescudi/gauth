package coreplainauth

import (
	"errors"
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/auth"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
	"github.com/scott-mescudi/gauth/shared/variables"
)

func TestLogin(t *testing.T) {
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

	_, err = pool.AddUser(t.Context(), "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	pa := &Coreplainauth{DB: pool, AccessTokenExpiration: 1 * time.Hour, RefreshTokenExpiration: 48 * time.Hour}

	tests := []struct {
		name        string
		identifier  string
		password    string
		expectedErr error
	}{
		{
			name:        "valid username login",
			identifier:  "jack",
			password:    "hey",
			expectedErr: nil,
		},
		{
			name:        "valid email login",
			identifier:  "jack@jack.com",
			password:    "hey",
			expectedErr: nil,
		},
		{
			name:        "empty identifier login",
			identifier:  "",
			password:    "hey",
			expectedErr: errs.ErrEmptyCredentials,
		},
		{
			name:        "empty password login",
			identifier:  "jack@jack.com",
			password:    "",
			expectedErr: errs.ErrEmptyCredentials,
		},
		{
			name:        "Invalid password login",
			identifier:  "jack@jack.com",
			password:    "hsey",
			expectedErr: errs.ErrIncorrectPassword,
		},
		{
			name:        "non existant identidier login",
			identifier:  "jsdacsdfsd",
			password:    "hsey",
			expectedErr: errs.ErrNoUserFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			at, rt, err := pa.LoginHandler(t.Context(), tt.identifier, tt.password, "")

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

func BenchmarkLogin(b *testing.B) {
	conn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		b.Fatal(err)
	}

	defer clean()

	pool, err := database.ConnectToDatabase("postgres", conn)
	if err != nil {
		b.Fatal(err)
	}

	ph, err := HashPassword("hey")
	if err != nil {
		b.Fatal(err)
	}

	_, err = pool.AddUser(b.Context(), "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		b.Fatal(err)
	}

	pa := &Coreplainauth{DB: pool, AccessTokenExpiration: 1 * time.Hour, RefreshTokenExpiration: 48 * time.Hour}

	b.ResetTimer()
	for b.Loop() {
		pa.LoginHandler(b.Context(), "jack", "hey", "")
	}
}

//       25          43001044 ns/op           13479 B/op        155 allocs/op
