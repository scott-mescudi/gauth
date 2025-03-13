package coreplainauth

import (
	"strings"
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/auth"
	"github.com/scott-mescudi/gauth/shared/email"
	"github.com/scott-mescudi/gauth/shared/hashing"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
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
				LoginTemplate:             "",
				SignupTemplate:            "",
				DeleteAccountTemplate:     "",
				UpdatePasswordTemplate:    "",
			},
		}

		err = pa.VerifiedUpdatePassword(t.Context(), uid, "hey", "heyq2")
		if err != nil {
			t.Fatal(err)
		}

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
				LoginTemplate:             "",
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
