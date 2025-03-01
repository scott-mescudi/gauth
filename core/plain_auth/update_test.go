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

	uid, err := conn.AddUser(t.Context(), "jack", "jack@jack.com", "user", ph, true)
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
			err := app.UpdatePasswordHandler(uid, tt.oldPass, tt.newPass)
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

	uid, err := conn.AddUser(t.Context(), "jack", "jack@jack.com", "user", ph, true)
	if err != nil {
		t.Fatal(err)
	}

	app := &Coreplainauth{DB: conn}

	tests := []struct {
		name        string
		oldEmail    string
		newEmail    string
		expectedErr error
	}{
		{
			name:        "valid change",
			oldEmail:    "jack@jack.com",
			newEmail:    "jacsk@jack.com",
			expectedErr: nil,
		},
		{
			name:        "invalid old email",
			oldEmail:    "jack@jack.com",
			newEmail:    "jacsk@jack.com",
			expectedErr: errs.ErrEmailMismatch,
		},
		{
			name:        "invalid new email",
			oldEmail:    "jack@jack.com",
			newEmail:    "jacskjack.com",
			expectedErr: errs.ErrInvalidEmail,
		},
		{
			name:        " email to long",
			oldEmail:    "jack@jack.com",
			newEmail:    string(make([]byte, 345)),
			expectedErr: errs.ErrEmailTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := app.UpdateEmailHandler(uid, tt.oldEmail, tt.newEmail)
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Got %v expected %v", err, tt.expectedErr)
			}
		})
	}
}
