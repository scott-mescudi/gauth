package plainauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	au "github.com/scott-mescudi/gauth/core"
	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/middlewares"
	"github.com/scott-mescudi/gauth/shared/auth"
	"github.com/scott-mescudi/gauth/shared/email"
	"github.com/scott-mescudi/gauth/shared/logger"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestVerifiedDeleteAccount(t *testing.T) {
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
			UpdateEmailTemplate:         "",
			CancelUpdateEmailTemplate:   "",
			CancelDeleteAccountTemplate: "",
			SignupTemplate:              "",
			DeleteAccountTemplate:       "",
			UpdatePasswordTemplate:      "",
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

	at, _, err := pa.LoginHandler(t.Context(), "jack", "hey", "")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid Delete", func(t *testing.T) {
		defer func() {
			fmt.Println(logs.String())
		}()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/user/account", http.NoBody)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", at)

		z := &middlewares.MiddlewareConfig{JWTConfig: x}

		bldr.Reset()
		handler := z.AuthMiddleware(http.HandlerFunc(af.VerifiedDeleteAccount))
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Got %v, Expected %v", rec.Code, http.StatusOK)
		}

		time.Sleep(3 * time.Second)
		token := bldr.String()[:len("f895e4e1-620b-4914-979e-e6837676f461")]

		rec = httptest.NewRecorder()
		req = httptest.NewRequest("DELETE", fmt.Sprintf("/auth/user/verify/account?token=%v", token), http.NoBody)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", at)

		handler = z.AuthMiddleware(http.HandlerFunc(af.VerifyDeleteAccount))
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusPermanentRedirect {
			fmt.Println(rec.Body)
			t.Errorf("Got %v, Expected %v", rec.Code, http.StatusPermanentRedirect)
		}
	})
}

func TestVerifiedDeleteAccountCancel(t *testing.T) {
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
			UpdateEmailTemplate:         "",
			CancelUpdateEmailTemplate:   "",
			CancelDeleteAccountTemplate: "",
			SignupTemplate:              "",
			DeleteAccountTemplate:       "",
			UpdatePasswordTemplate:      "",
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

	at, _, err := pa.LoginHandler(t.Context(), "jack", "hey", "")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid Delete", func(t *testing.T) {
		defer func() {
			fmt.Println(logs.String())
		}()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("DELETE", "/user/account", http.NoBody)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", at)

		z := &middlewares.MiddlewareConfig{JWTConfig: x}

		bldr.Reset()
		handler := z.AuthMiddleware(http.HandlerFunc(af.VerifiedDeleteAccount))
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Got %v, Expected %v", rec.Code, http.StatusOK)
		}

		time.Sleep(3 * time.Second)
		token := bldr.String()[:len("f895e4e1-620b-4914-979e-e6837676f461")]

		rec = httptest.NewRecorder()
		req = httptest.NewRequest("DELETE", fmt.Sprintf("/auth/user/verify/account?token=%v", token), http.NoBody)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", at)

		handler = z.AuthMiddleware(http.HandlerFunc(af.CancelDeleteAccount))
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusPermanentRedirect {
			fmt.Println(rec.Body)
			t.Errorf("Got %v, Expected %v", rec.Code, http.StatusPermanentRedirect)
		}

		_, _, err = pa.LoginHandler(t.Context(), "jack", "hey", "")
		if err != nil {
			t.Fatal(err)
		}
	})
}
