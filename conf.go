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


	if config.OauthConfig != nil { 
		api.OauthConfig = &plainauth.OauthConfig{}
	}

	if config.OauthConfig != nil && config.OauthConfig.Github != nil {
		api.OauthConfig.Github = &oauth2.Config{
			ClientID:     config.OauthConfig.Github.ClientID,
			ClientSecret: config.OauthConfig.Github.ClientSecret,
			RedirectURL:  config.OauthConfig.Domain + "/github/callback",
			Scopes:       []string{"read:user"},
			Endpoint:     github.Endpoint,
		}

		config.routes = append(config.routes, Route{Method: "", Path: "/github", Handler: "HandleGithubLogin"})
		mux.HandleFunc("/github", api.HandleGithubLogin)
		mux.HandleFunc("/github/callback", api.GithubOauthCallback)
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

	// missing delete route
	if config.EmailAndPassword {
		routes := []Route{
			{Method: "POST", Path: "/auth/login", Handler: "Login"},
			{Method: "POST", Path: "/auth/token/refresh", Handler: "Refresh"},
			{Method: "POST", Path: "/auth/logout", Handler: "Logout"},
			{Method: "GET", Path: "/auth/user/profile", Handler: "GetUserDetails"},
			{Method: "POST", Path: "/auth/user/avatar", Handler: "UploadProfileImage"},
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
				{Method: "POST", Path: "/auth/register", Handler: "VerifiedSignup"},
				{Method: "POST", Path: "/auth/user/email", Handler: "VerifiedUpdateEmail"},
				{Method: "POST", Path: "/auth/user/password", Handler: "VerifiedUpdatePassword"},
				{Method: "", Path: "/auth/verify/cancel-email-update", Handler: "CancelUpdateEmail"},
				{Method: "", Path: "/auth/verify/register", Handler: "VerifySignup"},
				{Method: "", Path: "/auth/verify/password-update", Handler: "VerifyUpdatePassword"},
				{Method: "", Path: "/auth/verify/email-update", Handler: "VerifyUpdateEmail"},
				{Method: "DELETE", Path: "/auth/account", Handler: "VerifiedDeleteAccount"},
				{Method: "", Path: "/auth/verify/account-delete", Handler: "VerifyDeleteAccount"},
				{Method: "", Path: "/auth/verify/cancel-account-delete", Handler: "CancelDeleteAccount"},
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
			mux.Handle("/auth/verify/cancel-email-update", z.AuthMiddleware(api.CancelUpdateEmail))

			mux.HandleFunc("/auth/verify/register", api.VerifySignup)
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

			if r2 != nil {
				mux.Handle("POST /auth/user/email", r2.RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					z.AuthMiddleware(api.UpdateEmail).ServeHTTP(w, r)
				})))
				mux.Handle("POST /auth/user/password", r2.RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					z.AuthMiddleware(api.UpdatePassword).ServeHTTP(w, r)
				})))
				mux.Handle("POST /auth/user/username", r2.RateLimiter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					z.AuthMiddleware(api.UpdateUsername).ServeHTTP(w, r)
				})))
			} else {
				mux.Handle("POST /auth/user/email", z.AuthMiddleware(api.UpdateEmail))
				mux.Handle("POST /auth/user/password", z.AuthMiddleware(api.UpdatePassword))
				mux.Handle("POST /auth/user/username", z.AuthMiddleware(api.UpdateUsername))
			}

			routes = append(routes, extraRoutes...)
		}

		config.routes = append(config.routes, routes...)
	}



	return cleanup, nil
}

func (s *GauthConfig) GetRoutes() []Route {
	return s.routes
}
