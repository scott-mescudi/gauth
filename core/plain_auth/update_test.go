package coreplainauth

import (
	"errors"
	"testing"

	"github.com/scott-mescudi/gauth/database"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestUpdatePasswordHandler(t *testing.T) {
	dsn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	conn, err := database.ConnectToDatabase("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	uid, err := conn.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	app := &Coreplainauth{DB: conn}

	tests := []struct {
		name        string
		oldPass     string
		newPass     string
		expectedErr error
	}{
		{
			name:        "valid change",
			oldPass:     "hey",
			newPass:     "wait",
			expectedErr: nil,
		},
		{
			name:        "wrong old password",
			oldPass:     "sdfsd",
			newPass:     "wait",
			expectedErr: errs.ErrIncorrectPassword,
		},
		{
			name:        "to long password",
			oldPass:     "wait",
			newPass:     string(make([]byte, 304)),
			expectedErr: errs.ErrPasswordTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := app.UpdatePasswordHandler(t.Context(), uid, tt.oldPass, tt.newPass)
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Got %v expected %v", err, tt.expectedErr)
			}
		})
	}
}

func TestUpdateEmailHandler(t *testing.T) {
	dsn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	conn, err := database.ConnectToDatabase("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	uid, err := conn.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	app := &Coreplainauth{DB: conn}

	tests := []struct {
		name        string
		newEmail    string
		expectedErr error
	}{
		{
			name:        "valid change",
			newEmail:    "jacsk@jack.com",
			expectedErr: nil,
		},
		{
			name:        "invalid new email",
			newEmail:    "jacskjack.com",
			expectedErr: errs.ErrInvalidEmail,
		},
		{
			name:        " email to long",
			newEmail:    string(make([]byte, 345)),
			expectedErr: errs.ErrEmailTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := app.UpdateEmailHandler(t.Context(), uid, tt.newEmail)
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Got %v expected %v", err, tt.expectedErr)
			}
		})
	}
}

func TestUpdateUsernameHandler(t *testing.T) {
	dsn, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	conn, err := database.ConnectToDatabase("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}

	ph, err := HashPassword("hey")
	if err != nil {
		t.Fatal(err)
	}

	uid, err := conn.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	app := &Coreplainauth{DB: conn}

	tests := []struct {
		name        string
		newUsername string
		expectedErr error
	}{
		{
			name:        "valid change",
			newUsername: "jacsk",
			expectedErr: nil,
		},
		{
			name:        "invalid new username",
			newUsername: "",
			expectedErr: errs.ErrEmptyField,
		},
		{
			name:        " username to long",
			newUsername: string(make([]byte, 345)),
			expectedErr: errs.ErrUsernameTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := app.UpdateUsernameHandler(t.Context(), uid, tt.newUsername)
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Got %v expected %v", err, tt.expectedErr)
			}
		})
	}
}
