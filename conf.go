package gauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
	plainauth "github.com/scott-mescudi/gauth/api/stdlib"
	coreplainauth "github.com/scott-mescudi/gauth/core"
	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/middlewares"
	"github.com/scott-mescudi/gauth/shared/auth"
	"github.com/scott-mescudi/gauth/shared/ratelimiter"
	"github.com/scott-mescudi/gauth/shared/variables"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

func validateConfig(config *GauthConfig) error {
	validate := validator.New()
	return validate.Struct(config)
}

func (config *GauthConfig) rateLimit(auth, update bool) (authLimiter, updateLimiter *ratelimiter.GauthLimiter) {
	var r1 *ratelimiter.GauthLimiter
	var r2 *ratelimiter.GauthLimiter

	if auth {
		r1 = ratelimiter.NewGauthLimiter(uint64(config.RateLimitConfig.AuthLimit.TokenCount), config.RateLimitConfig.AuthLimit.CooldownPeriod, config.RateLimitConfig.AuthLimit.CooldownPeriod, config.RateLimitConfig.AuthLimit.CleanupInterval)
	}

	if update {
		r2 = ratelimiter.NewGauthLimiter(uint64(config.RateLimitConfig.UpdateLimit.TokenCount), config.RateLimitConfig.UpdateLimit.CooldownPeriod, config.RateLimitConfig.UpdateLimit.CooldownPeriod, config.RateLimitConfig.UpdateLimit.CleanupInterval)
	}

	return r1, r2
}

func RegisterOauthRoutes(config *GauthConfig, api *plainauth.PlainAuthAPI, mux *http.ServeMux) {
	if config.OauthConfig != nil {
		api.OauthConfig = &plainauth.OauthConfig{}
	}

	if config.OauthConfig != nil && config.OauthConfig.Github != nil {
		api.OauthConfig.Github = &oauth2.Config{
			ClientID:     config.OauthConfig.Github.ClientID,
			ClientSecret: config.OauthConfig.Github.ClientSecret,
			RedirectURL:  config.OauthConfig.Domain + "/auth/github/callback",
			Scopes:       []string{"read:user"},
			Endpoint:     github.Endpoint,
		}

		config.routes = append(config.routes, Route{Method: "GET", Path: "/auth/github", Handler: "HandleGithubLogin"})
		mux.HandleFunc("/auth/github", api.HandleGithubLogin)
		mux.HandleFunc("/auth/github/callback", api.GithubOauthCallback)
	}

	if config.OauthConfig != nil && config.OauthConfig.Google != nil {
		api.OauthConfig.Google = &oauth2.Config{
			ClientID:     config.OauthConfig.Google.ClientID,
			ClientSecret: config.OauthConfig.Google.ClientSecret,
			RedirectURL:  config.OauthConfig.Domain + "/auth/google/callback",
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
			Endpoint:     google.Endpoint,
		}

		config.routes = append(config.routes, Route{Method: "GET", Path: "/auth/google", Handler: "HandleGoogleLogin"})
		mux.HandleFunc("/auth/google", api.HandleGoogleLogin)
		mux.HandleFunc("/auth/google/callback", api.GoogleOauthCallback)
	}
}

func RegisterEmailPasswordRoutes(config *GauthConfig, api *plainauth.PlainAuthAPI, mux *http.ServeMux, r1 *ratelimiter.GauthLimiter, r2 *ratelimiter.GauthLimiter, z *middlewares.MiddlewareConfig) {
	if config.EmailAndPassword {
		routes := []Route{
			{Method: "POST", Path: "/auth/login", Handler: "Login", Description: "Authenticate user and start session"},
			{Method: "POST", Path: "/auth/token/refresh", Handler: "Refresh", Description: "Refresh authentication token"},
			{Method: "POST", Path: "/auth/logout", Handler: "Logout", Description: "End user session"},
			{Method: "GET", Path: "/auth/user/profile", Handler: "GetUserDetails", Description: "Fetch user profile details"},
			{Method: "POST", Path: "/auth/user/avatar", Handler: "UploadProfileImage", Description: "Upload new profile image as a base64 string"},
		}

		if r1 != nil {
			mux.Handle("POST /auth/login", r1.RateLimiter(api.Login))
		} else {
			mux.HandleFunc("POST /auth/login", api.Login)
		}

		mux.HandleFunc("POST /auth/token/refresh", api.Refresh)
		mux.Handle("POST /auth/logout", z.AuthMiddleware(api.Logout))
		mux.Handle("GET /auth/user/profile", z.AuthMiddleware(api.GetUserDetails))
		mux.Handle("POST /auth/user/avatar", z.AuthMiddleware(api.UploadProfileImage))

		if config.EmailConfig != nil {
			extraRoutes := []Route{
				{Method: "POST", Path: "/auth/register", Handler: "VerifiedSignup", Description: "Register a new user with email verification"},
				{Method: "POST", Path: "/auth/user/email", Handler: "VerifiedUpdateEmail", Description: "Update user email with verification"},
				{Method: "POST", Path: "/auth/user/password", Handler: "VerifiedUpdatePassword", Description: "Change user password with verification"},
				{Method: "GET", Path: "/auth/verify/cancel-email-update", Handler: "CancelUpdateEmail", Description: "Cancel pending email update"},
				{Method: "GET", Path: "/auth/verify/register", Handler: "VerifySignup", Description: "Verify email registration"},
				{Method: "GET", Path: "/auth/verify/password-update", Handler: "VerifyUpdatePassword", Description: "Verify password update"},
				{Method: "GET", Path: "/auth/verify/email-update", Handler: "VerifyUpdateEmail", Description: "Verify email update"},
				{Method: "DELETE", Path: "/auth/account", Handler: "VerifiedDeleteAccount", Description: "Delete user account with verification"},
				{Method: "GET", Path: "/auth/verify/account-delete", Handler: "VerifyDeleteAccount", Description: "Verify account deletion"},
				{Method: "GET", Path: "/auth/verify/cancel-account-delete", Handler: "CancelDeleteAccount", Description: "Cancel account deletion request"},
			}

			if r1 != nil {
				mux.Handle("POST /auth/register", r1.RateLimiter(api.VerifiedSignup))
			} else {
				mux.HandleFunc("POST /auth/register", api.VerifiedSignup)
			}

			if r2 != nil {
				mux.Handle("POST /auth/user/email", r2.RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					z.AuthMiddleware(api.VerifiedUpdateEmail).ServeHTTP(w, r)
				})))
				mux.Handle("POST /auth/user/password", r2.RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					z.AuthMiddleware(api.VerifiedUpdatePassword).ServeHTTP(w, r)
				})))
			} else {
				mux.Handle("POST /auth/user/email", z.AuthMiddleware(api.VerifiedUpdateEmail))
				mux.Handle("POST /auth/user/password", z.AuthMiddleware(api.VerifiedUpdatePassword))
			}

			mux.Handle("DELETE /auth/account", z.AuthMiddleware(api.VerifiedDeleteAccount))
			mux.Handle("GET /auth/verify/cancel-email-update", z.AuthMiddleware(api.CancelUpdateEmail))

			mux.HandleFunc("GET /auth/verify/register", api.VerifySignup)
			mux.HandleFunc("GET /auth/verify/password-update", api.VerifyUpdatePassword)
			mux.HandleFunc("GET /auth/verify/email-update", api.VerifyUpdateEmail)
			mux.HandleFunc("GET /auth/verify/account-delete", api.VerifyDeleteAccount)
			mux.HandleFunc("GET /auth/verify/cancel-account-delete", api.CancelDeleteAccount)

			routes = append(routes, extraRoutes...)
		}

		extraRoutes := []Route{
			{Method: "POST", Path: "/auth/no-verify/register", Handler: "Signup", Description: "Register a new user (no email verification)"},
			{Method: "POST", Path: "/auth/no-verify/user/email", Handler: "UpdateEmail", Description: "Update user email (no email verification)"},
			{Method: "POST", Path: "/auth/no-verify/user/password", Handler: "UpdatePassword", Description: "Update user password (no email verification)"},
			{Method: "POST", Path: "/auth/no-verify/user/username", Handler: "UpdateUsername", Description: "Update user username (no email verification)"},
			{Method: "DELETE", Path: "/auth/no-verify/account", Handler: "DeleteAccount", Description: "Delete user account (no email verification)"},
		}

		mux.Handle("DELETE /auth/no-verify/account", z.AuthMiddleware(api.DeleteAccount))
		mux.HandleFunc("POST /auth/no-verify/register", api.Signup)

		if r2 != nil {
			mux.Handle("POST /auth/no-verify/user/email", r2.RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				z.AuthMiddleware(api.UpdateEmail).ServeHTTP(w, r)
			})))
			mux.Handle("POST /auth/no-verify/user/password", r2.RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				z.AuthMiddleware(api.UpdatePassword).ServeHTTP(w, r)
			})))
			mux.Handle("POST /auth/no-verify/user/username", r2.RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				z.AuthMiddleware(api.UpdateUsername).ServeHTTP(w, r)
			})))
		} else {
			mux.Handle("POST /auth/no-verify/user/email", z.AuthMiddleware(api.UpdateEmail))
			mux.Handle("POST /auth/no-verify/user/password", z.AuthMiddleware(api.UpdatePassword))
			mux.Handle("POST /auth/no-verify/user/username", z.AuthMiddleware(api.UpdateUsername))
		}

		routes = append(routes, extraRoutes...)

		config.routes = append(config.routes, routes...)
	}
}

func ParseConfig(config *GauthConfig, mux *http.ServeMux) (func(), error) {
	err := validateConfig(config)
	if err != nil {
		return nil, err
	}

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

	if config.JwtConfig == nil {
		db.Close()
		return nil, fmt.Errorf("error: incomplete JwtConfig")
	}

	if config.JwtConfig.AccessTokenExpiration == 0 || config.JwtConfig.RefreshTokenExpiration == 0 {
		db.Close()
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
	r1, r2 := config.rateLimit(config.RateLimitConfig.AuthLimit != nil, config.RateLimitConfig.UpdateLimit != nil)
	cleanup := func() {
		db.Close()

		if r1 != nil {
			r1.Shutdown()
		}

		if r2 != nil {
			r2.Shutdown()
		}
	}

	RegisterOauthRoutes(config, api, mux)
	RegisterEmailPasswordRoutes(config, api, mux, r1, r2, z)

	return cleanup, nil
}

func (s *GauthConfig) GetRoutes() []Route {
	return s.routes
}
