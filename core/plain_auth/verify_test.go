package coreplainauth

import (
	"strings"
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/email"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestVerifyPassword(t *testing.T) {
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

	bldr := strings.Builder{}
	app := &Coreplainauth{
		DB:                     conn,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		EmailProvider:          &email.MockClient{Writer: &bldr},
	}

	err = app.VerifiedUpdatePasswordHandler(t.Context(), uid, "hey", "hey2")
	if err != nil {
		t.Fatal(err)
	}

	err = app.VerifyUpdatePasswordToken(t.Context(), bldr.String())
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEmail(t *testing.T) {
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

	bldr := strings.Builder{}
	app := &Coreplainauth{
		DB:                     conn,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		EmailProvider:          &email.MockClient{Writer: &bldr},
	}

	err = app.VerifiedUpdateEmailHandler(t.Context(), uid, "hey@2.com")
	if err != nil {
		t.Fatal(err)
	}

	err = app.VerifyUpdateEmailToken(t.Context(), bldr.String())
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyUsername(t *testing.T) {
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

	bldr := strings.Builder{}
	app := &Coreplainauth{
		DB:                     conn,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		EmailProvider:          &email.MockClient{Writer: &bldr},
	}

	err = app.VerifiedUpdateUsernameHandler(t.Context(), uid, "ko-kong")
	if err != nil {
		t.Fatal(err)
	}

	err = app.VerifyUpdateUsernameToken(t.Context(), bldr.String())
	if err != nil {
		t.Fatal(err)
	}
}
