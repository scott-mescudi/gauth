package coreplainauth

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/pkg/auth"
	"github.com/scott-mescudi/gauth/pkg/email"
	"github.com/scott-mescudi/gauth/pkg/logger"
	tu "github.com/scott-mescudi/gauth/pkg/testutils"
)

func TestGithub(t *testing.T) {
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

	_, _, err = pa.HandleGithubOauth(t.Context(), "", "", "hellowrold")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = pa.HandleGithubOauth(t.Context(), "", "", "hellowrold")
	if err != nil {
		t.Fatal(err)
	}
}
