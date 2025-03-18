package coreplainauth

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/pkg/auth"
	"github.com/scott-mescudi/gauth/pkg/email"
	"github.com/scott-mescudi/gauth/pkg/hashing"
	"github.com/scott-mescudi/gauth/pkg/logger"
	tu "github.com/scott-mescudi/gauth/pkg/testutils"
)

func TestDeleteUser(t *testing.T) {
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

	log := &strings.Builder{}
	bldr := &strings.Builder{}
	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
		EmailProvider:          &email.MockClient{Writer: bldr},
		EmailTemplateConfig: &EmailTemplateConfig{
			UpdateEmailTemplate:       "",
			CancelUpdateEmailTemplate: "",
			SignupTemplate:            "",
			DeleteAccountTemplate:     "",
			UpdatePasswordTemplate:    "",
		},
		Logger: logger.NewDefaultGauthLogger(log),
	}

	t.Run("valid delete", func(t *testing.T) {
		err = pa.DeleteAccount(t.Context(), uid)
		if err != nil {
			t.Fatal("failed to delete account")
		}
	})
}

func TestVerifiedDeleteUser(t *testing.T) {
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

	uid2, err := pool.AddUser(t.Context(), "", "", "jascks", "jacsdk@sdjack.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	log := &strings.Builder{}
	bldr := &strings.Builder{}
	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
		EmailProvider:          &email.MockClient{Writer: bldr},
		EmailTemplateConfig: &EmailTemplateConfig{
			UpdateEmailTemplate:       "",
			CancelUpdateEmailTemplate: "",
			SignupTemplate:            "",
			DeleteAccountTemplate:     "",
			UpdatePasswordTemplate:    "",
		},
		Logger: logger.NewDefaultGauthLogger(log),
	}

	defer func() {
		fmt.Println(log)
	}()

	t.Run("canceled delete", func(t *testing.T) {
		err = pa.VerifiedDeleteAccount(t.Context(), uid)
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(1 * time.Second)
		token := bldr.String()[:len("f895e4e1-620b-4914-979e-e6837676f461")]

		err = pa.CancelDeleteAccount(t.Context(), token)
		if err != nil {
			t.Fatal("failed to cancel delete account")
		}

		_, _, err = pa.login(t.Context(), "jack", "hey", "")
		if err != nil {
			t.Fatal(err)
		}

		bldr.Reset()
	})

	t.Run("valid delete", func(t *testing.T) {
		err = pa.VerifiedDeleteAccount(t.Context(), uid2)
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(1 * time.Second)
		token := bldr.String()[:len("f895e4e1-620b-4914-979e-e6837676f461")]

		err = pa.VerifyDeleteAccount(t.Context(), token)
		if err != nil {
			t.Fatal("failed to delete account")
		}
		bldr.Reset()
	})

}
