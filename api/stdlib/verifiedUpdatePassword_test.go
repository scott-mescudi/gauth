package plainauth

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	au "github.com/scott-mescudi/gauth/core"
	"github.com/scott-mescudi/gauth/database"
	middlewares "github.com/scott-mescudi/gauth/middlewares/auth"

	"github.com/scott-mescudi/gauth/pkg/auth"
	"github.com/scott-mescudi/gauth/pkg/email"
	"github.com/scott-mescudi/gauth/pkg/logger"
	tu "github.com/scott-mescudi/gauth/pkg/testutils"
)

func TestVerifiedPassword(t *testing.T) {
	connstr, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db, err := database.ConnectToDatabase("postgres", connstr)
	if err != nil {
		t.Fatal(err)
	}

	logs := &strings.Builder{}
	bldr := &strings.Builder{}
	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &au.Coreplainauth{
		DB:                     db,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
		EmailProvider:          &email.MockClient{Writer: bldr},
		Domain:                 "https://github.com/scott-mescudi/gauth",
		Logger:                 logger.NewDefaultGauthLogger(logs),
		EmailTemplateConfig: &au.EmailTemplateConfig{
			UpdateEmailTemplate:       "",
			CancelUpdateEmailTemplate: "",

			SignupTemplate:         "",
			DeleteAccountTemplate:  "",
			UpdatePasswordTemplate: "",
		},
	}

	af := &PlainAuthAPI{
		AuthCore: pa,
		RedirectConfig: &RedirectConfig{
			SignupComplete: "https://github.com/scott-mescudi/gauth",
			PasswordSet:    "https://github.com/scott-mescudi/gauth",
			EmailSet:       "https://github.com/scott-mescudi/gauth",
			UsernameSet:    "https://github.com/scott-mescudi/gauth",
		},
	}

	err = pa.SignupHandler(t.Context(), "", "", "jack", "jack@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	err = pa.SignupHandler(t.Context(), "", "", "jill", "jill@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	at, _, err := pa.LoginHandler(t.Context(), "jack", "hey", "")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid update", func(t *testing.T) {
		defer func() {
			fmt.Println(logs.String())
		}()
		rec := httptest.NewRecorder()
		body, err := json.Marshal(&updatePasswordRequest{
			OldPassword: "hey",
			NewPassword: "he2",
		})
		if err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest("POST", "/update/password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", at)

		z := &middlewares.MiddlewareConfig{JWTConfig: x}

		handler := z.AuthMiddleware(http.HandlerFunc(af.VerifiedUpdatePassword))
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Got %v, Expected %v", rec.Code, http.StatusOK)
		}

		time.Sleep(1 * time.Second)
		token := bldr.String()[:len("f895e4e1-620b-4914-979e-e6837676f461")]

		rec = httptest.NewRecorder()
		req = httptest.NewRequest("POST", fmt.Sprintf("/verify/password?token=%s", token), bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", at)

		handler = z.AuthMiddleware(http.HandlerFunc(af.VerifyUpdatePassword))
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusPermanentRedirect {
			fmt.Println(rec.Body)
			t.Errorf("Got %v, Expected %v", rec.Code, http.StatusPermanentRedirect)
		}
	})

}

func TestRecoverPassword(t *testing.T) {
	connstr, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db, err := database.ConnectToDatabase("postgres", connstr)
	if err != nil {
		t.Fatal(err)
	}

	logs := &strings.Builder{}
	bldr := &strings.Builder{}
	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &au.Coreplainauth{
		DB:                     db,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
		EmailProvider:          &email.MockClient{Writer: bldr},
		Domain:                 "https://github.com/scott-mescudi/gauth",
		Logger:                 logger.NewDefaultGauthLogger(logs),
		EmailTemplateConfig: &au.EmailTemplateConfig{
			UpdateEmailTemplate:       "",
			CancelUpdateEmailTemplate: "",
			RecoverAccountTemplate:    "",
			SignupTemplate:            "",
			DeleteAccountTemplate:     "",
			UpdatePasswordTemplate:    "",
		},
	}

	af := &PlainAuthAPI{
		AuthCore: pa,
		RedirectConfig: &RedirectConfig{
			SignupComplete: "https://github.com/scott-mescudi/gauth",
			PasswordSet:    "https://github.com/scott-mescudi/gauth",
			EmailSet:       "https://github.com/scott-mescudi/gauth",
			UsernameSet:    "https://github.com/scott-mescudi/gauth",
		},
	}

	err = pa.SignupHandler(t.Context(), "", "", "jack", "jack@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	body, err := json.Marshal(&HandleRecoverPasswordRequest{
		Email: "jack@jack.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/auth/recover/password", bytes.NewReader(body))
	af.HandleRecoverPassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal("failed to generate recover token")
	}

	time.Sleep(1 * time.Second)
	token := bldr.String()

	rec = httptest.NewRecorder()
	body, err = json.Marshal(&RecoverPasswordRequest{
		Token:       token,
		NewPassword: "sigma",
	})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "/auth/recover/password/reset", bytes.NewReader(body))
	af.RecoverPassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal("failed to generate recover token")
	}
}
