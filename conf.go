package gauth

import (
	"context"
	"fmt"
	"net/http"

	plainauth "github.com/scott-mescudi/gauth/api/stdlib/plain_auth"
	coreplainauth "github.com/scott-mescudi/gauth/core/plain_auth"
	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/middlewares"
	"github.com/scott-mescudi/gauth/shared/auth"
	"github.com/scott-mescudi/gauth/shared/variables"
)

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

	if config.JwtConfig == nil {
		cleanup()
		return nil, fmt.Errorf("error: incomplete JwtConfig")
	}

	if config.JwtConfig.AccessTokenExpiration == 0 || config.JwtConfig.RefreshTokenExpiration == 0 {
		cleanup()
		return nil, fmt.Errorf("error: incomplete JWT token config")
	}

	jwt := &auth.JWTConfig{
		Issuer: config.JwtConfig.Issuer,
		Secret: config.JwtConfig.Secret,
	}

	api := &plainauth.PlainAuthAPI{
		AuthCore: &coreplainauth.Coreplainauth{
			DB:                     db,
			AccessTokenExpiration:  config.JwtConfig.AccessTokenExpiration,
			RefreshTokenExpiration: config.JwtConfig.RefreshTokenExpiration,
			Logger:                 config.Logger,
			JWTConfig:              jwt,
		},
		Cookie:         config.Cookie,
		Fingerprinting: config.Fingerprinting,
	}

	if config.Webhook != nil {
		api.AuthCore.WebhookConfig = &coreplainauth.WebhookConfig{
			CallbackURL:     config.Webhook.CallbackURL,
			Method:          config.Webhook.Method,
			AuthHeader:      config.Webhook.AuthHeader,
			AuthHeaderValue: config.Webhook.AuthHeaderValue,
		}
	}

	if config.EmailConfig != nil && config.EmailAndPassword {
		api.AuthCore.Domain = config.EmailConfig.AppDomain
		api.AuthCore.EmailProvider = config.EmailConfig.Provider

		if config.EmailConfig.TemplateConfig != nil {
			api.AuthCore.EmailTemplateConfig = &coreplainauth.EmailTemplateConfig{
				SignupTemplate:            config.EmailConfig.TemplateConfig.SignupTemplate,
				UpdatePasswordTemplate:    config.EmailConfig.TemplateConfig.UpdatePasswordTemplate,
				UpdateEmailTemplate:       config.EmailConfig.TemplateConfig.UpdateEmailTemplate,
				CancelUpdateEmailTemplate: config.EmailConfig.TemplateConfig.CancelUpdateEmailTemplate,
				DeleteAccountTemplate:     config.EmailConfig.TemplateConfig.DeleteAccountTemplate,
			}
		} else {
			api.AuthCore.EmailTemplateConfig = &coreplainauth.EmailTemplateConfig{
				SignupTemplate:            variables.SignupTemplate,
				UpdatePasswordTemplate:    variables.UpdatePasswordTemplate,
				UpdateEmailTemplate:       variables.UpdateEmailTemplate,
				CancelUpdateEmailTemplate: variables.CancelUpdateEmailTemplate,
				DeleteAccountTemplate:     variables.DeleteAccountTemplate,
			}
		}

		if config.EmailConfig.RedirectConfig != nil {
			api.RedirectConfig = &plainauth.RedirectConfig{
				SignupComplete: config.EmailConfig.RedirectConfig.SignupComplete,
				PasswordSet:    config.EmailConfig.RedirectConfig.PasswordSet,
				EmailSet:       config.EmailConfig.RedirectConfig.EmailSet,
				UsernameSet:    config.EmailConfig.RedirectConfig.UsernameSet,
			}
		} else {
			api.RedirectConfig = &plainauth.RedirectConfig{
				SignupComplete: config.EmailConfig.AppDomain,
				PasswordSet:    config.EmailConfig.AppDomain,
				EmailSet:       config.EmailConfig.AppDomain,
				UsernameSet:    config.EmailConfig.AppDomain,
			}
		}
	}

	z := &middlewares.MiddlewareConfig{JWTConfig: jwt}

	// missing delete, refresh, logout route
	if config.EmailAndPassword {
		mux.HandleFunc("POST /login", api.Login)
		mux.Handle("GET /user/details", z.AuthMiddleware(api.GetUserDetails))
		mux.Handle("POST /user/profile_picture", z.AuthMiddleware(api.UploadProfileImage))

		if config.EmailConfig != nil {
			mux.HandleFunc("POST /signup", api.VerifiedSignup)
			mux.Handle("POST /update/email", z.AuthMiddleware(api.VerifiedUpdateEmail))
			mux.Handle("POST /update/password", z.AuthMiddleware(api.VerifiedUpdatePassword))
			mux.Handle("POST /cancel/update/email", z.AuthMiddleware(api.CancelUpdateEmail))
			mux.HandleFunc("/verify/signup", api.VerifySignup)
			mux.HandleFunc("/verify/update-password", api.VerifyUpdatePassword)
			mux.HandleFunc("/verify/update-email", api.VerifyUpdateEmail)

		} else {
			mux.HandleFunc("POST /signup", api.Signup)
			mux.Handle("POST /update/email", z.AuthMiddleware(api.UpdateEmail))
			mux.Handle("POST /update/password", z.AuthMiddleware(api.UpdatePassword))
			mux.Handle("POST /update/username", z.AuthMiddleware(api.UpdateUsername))
		}
	}

	return cleanup, nil
}
