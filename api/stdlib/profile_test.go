package plainauth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	au "github.com/scott-mescudi/gauth/core"
	"github.com/scott-mescudi/gauth/database"
	middlewares "github.com/scott-mescudi/gauth/middlewares/auth"

	"github.com/scott-mescudi/gauth/shared/auth"
	"github.com/scott-mescudi/gauth/shared/email"
	"github.com/scott-mescudi/gauth/shared/logger"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestProfileImageLogic(t *testing.T) {
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

	at, _, err := pa.LoginHandler(t.Context(), "jack", "hey", "")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	body, err := json.Marshal(ProfileImageRequest{Base64Image: "data:image/png;base64," + base64.RawStdEncoding.EncodeToString(make([]byte, 100))})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/profile/image", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", at)

	z := &middlewares.MiddlewareConfig{JWTConfig: x}

	handler := z.AuthMiddleware(http.HandlerFunc(af.UploadProfileImage))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		fmt.Println(rec.Body)
		t.Errorf("Got %v, Expected %v", rec.Code, http.StatusOK)
	}
}

func TestGetUserDetails(t *testing.T) {
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

	z := &middlewares.MiddlewareConfig{JWTConfig: x}

	af := &PlainAuthAPI{
		AuthCore: pa,
		RedirectConfig: &RedirectConfig{
			SignupComplete: "https://github.com/scott-mescudi/gauth",
			PasswordSet:    "https://github.com/scott-mescudi/gauth",
			EmailSet:       "https://github.com/scott-mescudi/gauth",
			UsernameSet:    "https://github.com/scott-mescudi/gauth",
		},
	}

	err = pa.SignupHandler(t.Context(), "sdd", "jca", "jack", "jack@jack.com", "hey", "user", false)
	if err != nil {
		t.Fatal(err)
	}

	at, _, err := pa.LoginHandler(t.Context(), "jack", "hey", "")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()

	req := httptest.NewRequest("GET", "/user/details", http.NoBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", at)
	handler := z.AuthMiddleware(http.HandlerFunc(af.GetUserDetails))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		fmt.Println(rec.Body)
		t.Errorf("Got %v, Expected %v", rec.Code, http.StatusOK)
	}
}
