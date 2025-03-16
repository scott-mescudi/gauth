package coreplainauth

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/auth"
	"github.com/scott-mescudi/gauth/shared/email"
	"github.com/scott-mescudi/gauth/shared/logger"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
)

func TestGoogle(t *testing.T) {
	str, clean, err := tu.SetupTestPostgresDBConnStr("")
	if err != nil {
		t.Fatal(err)
	}

	defer clean()

	pool, err := database.ConnectToDatabase("postgres", str)
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
		fmt.Println(log.String())
	}()

	_, _, err = pa.HandleGoogleOauth(t.Context(), "", "", "hellowrold")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = pa.HandleGoogleOauth(t.Context(), "", "", "hellowrold")
	if err != nil {
		t.Fatal(err)
	}
}
