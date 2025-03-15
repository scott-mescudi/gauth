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

	// missing delete route
	if config.EmailAndPassword {
		routes := []Route{
			{Method: "POST", Path: "/auth/login", Handler: "Login"},
			{Method: "POST", Path: "/auth/token/refresh", Handler: "Refresh"},
			{Method: "POST", Path: "/auth/logout", Handler: "Logout"},
			{Method: "GET", Path: "/auth/user/profile", Handler: "GetUserDetails"},
			{Method: "POST", Path: "/auth/user/avatar", Handler: "UploadProfileImage"},
		}

		mux.HandleFunc("POST /auth/login", api.Login)
		mux.HandleFunc("POST /auth/token/refresh", api.Refresh)
		mux.Handle("POST /auth/logout", z.AuthMiddleware(api.Logout))
		mux.Handle("GET /auth/user/profile", z.AuthMiddleware(api.GetUserDetails))
		mux.Handle("POST /auth/user/avatar", z.AuthMiddleware(api.UploadProfileImage))

		if config.EmailConfig != nil {
			extraRoutes := []Route{
				{Method: "POST", Path: "/auth/register", Handler: "VerifiedSignup"},
				{Method: "POST", Path: "/auth/user/email", Handler: "VerifiedUpdateEmail"},
				{Method: "POST", Path: "/auth/user/password", Handler: "VerifiedUpdatePassword"},
				{Method: "", Path: "/auth/verify/cancel-email-update", Handler: "CancelUpdateEmail"},
				{Method: "", Path: "/auth/verify/signup", Handler: "VerifySignup"},
				{Method: "", Path: "/auth/verify/password-update", Handler: "VerifyUpdatePassword"},
				{Method: "", Path: "/auth/verify/email-update", Handler: "VerifyUpdateEmail"},
				{Method: "DELETE", Path: "/auth/account", Handler: "VerifiedDeleteAccount"},
				{Method: "", Path: "/auth/verify/account-delete", Handler: "VerifyDeleteAccount"},
				{Method: "", Path: "/auth/verify/cancel-account-delete", Handler: "CancelDeleteAccount"},
			}

			mux.HandleFunc("POST /auth/register", api.VerifiedSignup)
			mux.Handle("DELETE /auth/account", z.AuthMiddleware(api.VerifiedDeleteAccount))
			mux.Handle("POST /auth/user/email", z.AuthMiddleware(api.VerifiedUpdateEmail))
			mux.Handle("POST /auth/user/password", z.AuthMiddleware(api.VerifiedUpdatePassword))
			mux.Handle("/auth/verify/cancel-email-update", z.AuthMiddleware(api.CancelUpdateEmail))
			mux.HandleFunc("/auth/verify/signup", api.VerifySignup)
			mux.HandleFunc("/auth/verify/password-update", api.VerifyUpdatePassword)
			mux.HandleFunc("/auth/verify/email-update", api.VerifyUpdateEmail)
			mux.HandleFunc("/auth/verify/account-delete", api.VerifyDeleteAccount)
			mux.HandleFunc("/auth/verify/cancel-account-delete", api.CancelDeleteAccount)

			routes = append(routes, extraRoutes...)
		} else {
			extraRoutes := []Route{
				{Method: "POST", Path: "/auth/register", Handler: "Signup"},
				{Method: "POST", Path: "/auth/user/email", Handler: "UpdateEmail"},
				{Method: "POST", Path: "/auth/user/password", Handler: "UpdatePassword"},
				{Method: "POST", Path: "/auth/user/username", Handler: "UpdateUsername"},
				{Method: "DELETE", Path: "/auth/account", Handler: "DeleteAccount"},
			}

			mux.Handle("DELETE /auth/account", z.AuthMiddleware(api.DeleteAccount))
			mux.HandleFunc("POST /auth/register", api.Signup)
			mux.Handle("POST /auth/user/email", z.AuthMiddleware(api.UpdateEmail))
			mux.Handle("POST /auth/user/password", z.AuthMiddleware(api.UpdatePassword))
			mux.Handle("POST /auth/user/username", z.AuthMiddleware(api.UpdateUsername))

			routes = append(routes, extraRoutes...)
		}

		config.routes = append(config.routes, routes...)
	}

	return cleanup, nil
}

func (s *GauthConfig) GetRoutes() []Route {
	return s.routes
}
