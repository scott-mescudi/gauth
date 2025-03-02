package gauth

import (
	"context"
	"fmt"
	"net/http"

	plainauth "github.com/scott-mescudi/gauth/api/plain_auth"
	coreplainauth "github.com/scott-mescudi/gauth/core/plain_auth"
	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/email"
)

func isvalidEmailConfig(config *EmailConfig) bool {
	if config.ApiKey == "" {
		return false
	}

	if config.AppDomain == "" {
		return false
	}

	if config.EmailVerificationRedirectURL == "" {
		return false
	}

	if config.FromEmail == "" {
		return false
	}

	if config.FromName == "" {
		return false
	}

	return true
}

func ParseConfig(config *GauthConfig, mux *http.ServeMux) (func(), error) {
	if config.Database == nil || config.Database.Driver == "" || config.Database.Dsn == "" {
		return nil, fmt.Errorf("error: incomplete database config")
	}

	db, err := database.ConnectToDatabase(config.Database.Driver, config.Database.Dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(context.Background()); err != nil {
		return nil, err
	}

	db.Migrate()

	cleanup := func() {
		db.Close()
	}

	if config.AccessTokenExpiration == 0 || config.RefreshTokenExpiration == 0 {
		cleanup()
		return nil, fmt.Errorf("error: incomplete JWT token config")
	}

	api := &plainauth.PlainAuthAPI{
		AuthCore: &coreplainauth.Coreplainauth{
			DB:                     db,
			AccessTokenExpiration:  config.AccessTokenExpiration,
			RefreshTokenExpiration: config.RefreshTokenExpiration,
		},
	}

	if config.EmailConfig != nil {
		if !isvalidEmailConfig(config.EmailConfig) {
			return nil, fmt.Errorf("error: incomplete email config")
		}
		api = &plainauth.PlainAuthAPI{
			AuthCore: &coreplainauth.Coreplainauth{
				DB:                     db,
				AccessTokenExpiration:  config.AccessTokenExpiration,
				RefreshTokenExpiration: config.RefreshTokenExpiration,
				EmailProvider: &email.TwilioConfig{
					FromName:  config.EmailConfig.FromName,
					FromEmail: config.EmailConfig.FromEmail,
					ApiKey:    config.EmailConfig.ApiKey,
				},
				Domain: config.EmailConfig.AppDomain,
			},
			RedirectURL: config.EmailConfig.EmailVerificationRedirectURL,
		}

	}

	if config.EmailAndPassword {
		mux.HandleFunc("/login", api.Login)
		if config.EmailConfig != nil {
			mux.HandleFunc("/signup", api.VerifiedSignup)
			mux.HandleFunc("/verify", api.VerifySignup)
		} else {
			mux.HandleFunc("/signup", api.Signup)
		}
	}

	return cleanup, nil

}
