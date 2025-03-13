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

func TestVerifiedUpdateEmail(t *testing.T) {
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

	uid2, err := pool.AddUser(t.Context(), "", "", "jacks", "jacks@jacks.com", "user", hash, true)
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

		err = pa.VerifiedUpdateEmail(t.Context(), uid, "jack2@jack2.com")
		if err != nil {
			t.Fatal(err)
		}

		token := bldr.String()[:len("f895e4e1-620b-4914-979e-e6837676f461")]

		err = pa.VerifyUpdateEmail(t.Context(), token)
		if err != nil {
			t.Fatal(err)
		}

		email, err := pool.GetUserEmail(t.Context(), uid)
		if err != nil {
			t.Fatal(err)
		}

		if email != "jack2@jack2.com" {
			t.Fatal("failed to update email")
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

		err = pa.VerifiedUpdateEmail(t.Context(), uid2, "jack2s@jack2s.com")
		if err == nil {
			t.Fatal("failed to raise error")
		}
	})

	t.Run("cancel update", func(t *testing.T) {
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

		err = pa.VerifiedUpdateEmail(t.Context(), uid, "jack23@jack23.com")
		if err != nil {
			t.Fatal(err)
		}

		token := bldr.String()[:len("f895e4e1-620b-4914-979e-e6837676f461")]
		err = pa.CancelVerifyUpdateEmail(t.Context(), token)
		if err != nil {
			t.Fatal(err)
		}

		email, err := pool.GetUserEmail(t.Context(), uid)
		if err != nil {
			t.Fatal(err)
		}

		if email == "jack23@jack23.com" {
			t.Fatal("failed to cancel update email")
		}
	})
}
