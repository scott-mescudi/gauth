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

func TestVerifiedUpdatePassword(t *testing.T) {
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

	uid2, err := pool.AddUser(t.Context(), "", "", "jack2", "jack@jack2.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid update", func(t *testing.T) {
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
		}

		err = pa.VerifiedUpdatePassword(t.Context(), uid, "hey", "heyq2")
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(1 * time.Second)
		token := bldr.String()[:len("f895e4e1-620b-4914-979e-e6837676f461")]

		err = pa.VerifyUpdatePassword(t.Context(), token)
		if err != nil {
			t.Fatal(err)
		}

		password, err := pool.GetUserPasswordByID(t.Context(), uid)
		if err != nil {
			t.Fatal(err)
		}

		if password == hash {
			t.Fatal("failed to update password")
		}
	})

	t.Run("wrong signup method", func(t *testing.T) {
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
		}

		err = pool.SetSignupMethod(t.Context(), uid2, "github")
		if err != nil {
			t.Fatal(err)
		}

		err = pa.VerifiedUpdatePassword(t.Context(), uid2, "hey", "heyq2")
		if err == nil {
			t.Fatal("failed to raise error")
		}
	})
}

func TestRecoverPassword(t *testing.T) {
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

	_, err = pool.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := &strings.Builder{}
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
			RecoverAccountTemplate:    "",
		},
		Logger: logger.NewDefaultGauthLogger(logs),
	}

	defer func() {
		fmt.Println(logs.String())
	}()

	err = pa.HandleRecoverPassword(t.Context(), "jack@jack.com")
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1 * time.Second)
	token := bldr.String()

	err = pa.RecoverPassword(t.Context(), token, "jack")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = pa.login(t.Context(), "jack", "jack", "")
	if err != nil {
		t.Fatal(err)
	}
}
