package coreplainauth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"

	"github.com/scott-mescudi/gauth/pkg/auth"
	"github.com/scott-mescudi/gauth/pkg/compression"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
	"github.com/scott-mescudi/gauth/pkg/hashing"
	"github.com/scott-mescudi/gauth/pkg/logger"
	tu "github.com/scott-mescudi/gauth/pkg/testutils"
)

func TestUploadImage(t *testing.T) {
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

	logs := &strings.Builder{}

	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
		Domain:                 "https://github.com/scott-mescudi/gauth",
		Logger:                 logger.NewDefaultGauthLogger(logs),
		EmailTemplateConfig: &EmailTemplateConfig{
			UpdateEmailTemplate:       "",
			CancelUpdateEmailTemplate: "",

			SignupTemplate:         "",
			DeleteAccountTemplate:  "",
			UpdatePasswordTemplate: "",
		},
	}

	tests := []struct {
		name        string
		image       string
		expectedErr error
	}{
		{
			name:        "valid update",
			image:       "data:image/png;base64," + base64.RawStdEncoding.EncodeToString(make([]byte, 100)),
			expectedErr: nil,
		},
		{
			name:        "invalid update",
			image:       ":",
			expectedErr: errs.ErrInvalidBase64String,
		},
		{
			name:        "invalid update",
			image:       "data:image/png;base64," + base64.RawStdEncoding.EncodeToString(make([]byte, 5*1024*1024)),
			expectedErr: errs.ErrImageToLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pa.UploadImage(t.Context(), uid, tt.image)
			if err != tt.expectedErr {
				t.Errorf("Got %v, Expected %v", err, tt.expectedErr)
			}

		})
	}
}

func TestGetImage(t *testing.T) {
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

	uid2, err := pool.AddUser(t.Context(), "", "", "jack2", "jack2@jac2k.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := &strings.Builder{}

	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
		Domain:                 "https://github.com/scott-mescudi/gauth",
		Logger:                 logger.NewDefaultGauthLogger(logs),
		EmailTemplateConfig: &EmailTemplateConfig{
			UpdateEmailTemplate:       "",
			CancelUpdateEmailTemplate: "",

			SignupTemplate:         "",
			DeleteAccountTemplate:  "",
			UpdatePasswordTemplate: "",
		},
	}

	im := "data:image/png;base64," + base64.RawStdEncoding.EncodeToString(make([]byte, 100))
	com, err := compression.CompressZSTD([]byte(im))
	if err != nil {
		t.Fatal(err)
	}

	err = pool.SetUserImage(t.Context(), uid, com)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("get image", func(t *testing.T) {
		image, err := pa.GetImage(t.Context(), uid)
		if err != nil {
			t.Fatal(err)
		}

		if image != im {
			t.Fatal("image mismatch")
		}
	})

	t.Run("get null image", func(t *testing.T) {
		_, err := pa.GetImage(t.Context(), uid2)
		if !errors.Is(err, errs.ErrNoImageFound) {
			t.Fatal("failed to raise no imaeg found error")
		}
	})
}

func TestGetUserDetails(t *testing.T) {
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

	userid, err := pool.AddUser(t.Context(), "sdd", "jca", "jack", "jack@jack.com", "user", hash, true)
	if err != nil {
		t.Fatal(err)
	}

	logs := &strings.Builder{}

	x := &auth.JWTConfig{Issuer: "jack", Secret: []byte("ljahdrfbdcvlj.hsbdflhb")}
	pa := &Coreplainauth{
		DB:                     pool,
		AccessTokenExpiration:  1 * time.Hour,
		RefreshTokenExpiration: 48 * time.Hour,
		JWTConfig:              x,
		Domain:                 "https://github.com/scott-mescudi/gauth",
		Logger:                 logger.NewDefaultGauthLogger(logs),
		EmailTemplateConfig: &EmailTemplateConfig{
			UpdateEmailTemplate:       "",
			CancelUpdateEmailTemplate: "",

			SignupTemplate:         "",
			DeleteAccountTemplate:  "",
			UpdatePasswordTemplate: "",
		},
	}

	err = pa.UploadImage(t.Context(), userid, "data:image/png;base64,"+base64.RawStdEncoding.EncodeToString(make([]byte, 100)))
	if err != nil {
		t.Fatal(err)
	}

	info := &UserSessionDetails{}

	err = pa.GetUserDetails(t.Context(), userid, info)
	if err != nil {
		t.Fatal(err)
	}

	if info.Username != "jack" {
		t.Errorf("Expected username 'jack', got '%s'", info.Username)
	}

	if info.Email != "jack@jack.com" {
		t.Errorf("Expected email 'jack@jack.com', got '%s'", info.Email)
	}

	if info.FirstName != "sdd" {
		t.Errorf("Expected firstName 'jack', got '%s'", info.FirstName)
	}

	if info.LastName != "jca" {
		t.Errorf("Expected lastName 'jack', got '%s'", info.LastName)
	}

	if info.SignupMethod != "plain" {
		t.Errorf("Expected signupMethod 'hey', got '%s'", info.SignupMethod)
	}

	if info.Role != "user" {
		t.Errorf("Expected role 'user', got '%s'", info.Role)
	}

	if info.Created.IsZero() {
		t.Errorf("Expected a non-zero created time, got %v", info.Created)
	}
}
