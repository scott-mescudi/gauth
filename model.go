package gauth

import (
	"net/http"
	"time"

	"github.com/scott-mescudi/gauth/pkg/email"
	"github.com/scott-mescudi/gauth/pkg/logger"
)

// PoolConfig defines the configuration for database connection pooling.
type PoolConfig struct {
	// MaxConns specifies the maximum number of database connections allowed.
	MaxConns int `validate:"gte=1"`

	// MinConns specifies the minimum number of database connections to maintain in the pool.
	MinConns int `validate:"gte=0"`

	// MaxConnLifetime defines the maximum lifespan of a database connection before it is closed.
	MaxConnLifetime time.Duration `validate:"gte=0"`

	// MaxConnIdleTime defines the maximum idle time before a connection is closed.
	MaxConnIdleTime time.Duration `validate:"gte=0"`
}

// Database holds the configuration required to connect to a database.
type Database struct {
	// Driver specifies the database driver (e.g., "mysql", "postgres", "sqlite", "mongodb").
	Driver string `validate:"required"`

	// Dsn is the Data Source Name (DSN) used for the database connection.
	Dsn string `validate:"required"`

	// Config is an optional configuration for managing connection pooling.
	Config *PoolConfig
}

// JwtConfig defines settings for JSON Web Token (JWT) authentication.
type JwtConfig struct {
	// Issuer specifies the entity that issues the JWT.
	Issuer string `validate:"required"`

	// Secret is the secret key used for signing JWTs.
	Secret []byte `validate:"required"`

	// AccessTokenExpiration defines the expiration duration for access tokens.
	AccessTokenExpiration time.Duration `validate:"required,gt=0"`

	// RefreshTokenExpiration defines the expiration duration for refresh tokens.
	RefreshTokenExpiration time.Duration `validate:"required,gt=0"`
}

// EmailTemplateConfig defines customizable email templates for various authentication flows.
type EmailTemplateConfig struct {
	// SignupTemplate is the template used for user signup verification.
	SignupTemplate string `validate:"required"`

	// UpdatePasswordTemplate is the template used for password update requests.
	UpdatePasswordTemplate string `validate:"required"`

	// UpdateEmailTemplate is the template used for updating user email addresses.
	UpdateEmailTemplate string `validate:"required"`

	// CancelUpdateEmailTemplate is the template for canceling an email update request.
	CancelUpdateEmailTemplate string `validate:"required"`

	// DeleteAccountTemplate is the template for account deletion confirmation.
	DeleteAccountTemplate string `validate:"required"`

	// RecoverAccountTemplate is the template for account recovery emails.
	RecoverAccountTemplate string `validate:"required"`

	// LoginTemplate is the template used for login-related emails.
	LoginTemplate string `validate:"required"`
}

// WebhookConfig defines settings for integrating webhooks to receive authentication-related events.
type WebhookConfig struct {
	// CallbackURL is the URL where webhook events should be sent.
	CallbackURL string `validate:"required,url"`

	// Method is the HTTP method (POST/GET) used for webhook requests.
	Method string `validate:"required,oneof=POST GET"`

	// AuthHeader is the header key for webhook authentication (optional).
	AuthHeader string

	// AuthHeaderValue is the value for the authentication header (optional).
	AuthHeaderValue string
}

// EmailConfig holds the configuration required for email-based authentication and verification.
type EmailConfig struct {
	// Provider specifies the email service provider to use.
	Provider email.EmailProvider `validate:"required"`

	// AppDomain specifies the domain name of the application sending emails.
	AppDomain string `validate:"required"`

	// RedirectConfig holds the configuration for redirecting users after email verification.
	RedirectConfig *RedirectConfig `validate:"required"`
	
	// TemplateConfig holds email templates for authentication flows (optional).
	TemplateConfig *EmailTemplateConfig

}

// RedirectConfig defines redirection URLs after completing authentication steps.
type RedirectConfig struct {
	// SignupComplete is the URL to redirect users after signup verification.
	SignupComplete string `validate:"required,url"`

	// EmailSet is the URL to redirect users after setting their email.
	EmailSet string `validate:"required,url"`

	// PasswordSet is the URL to redirect users after updating their password.
	PasswordSet string `validate:"required,url"`

	// UsernameSet is the URL to redirect users after setting their username.
	UsernameSet string `validate:"required,url"`
}

// Limit defines rate-limiting configurations, such as token count and cooldown periods.
type Limit struct {
	// TokenCount specifies the number of tokens a user has before hitting the rate limit.
	TokenCount int `validate:"gte=1"`

	// CooldownPeriod specifies the duration a user must wait after using all tokens.
	CooldownPeriod time.Duration `validate:"gte=0"`

	// TimeInactive specifies the duration after which the user's activity is considered inactive.
	TimeInactive time.Duration `validate:"gte=0"`

	// CleanupInterval specifies how often to clean up inactive user data.
	CleanupInterval time.Duration `validate:"gte=0"`
}

// RateLimitConfig defines rate-limiting configurations for authentication and account update routes.
type RateLimitConfig struct {
	// AuthLimit defines rate limits for authentication routes (e.g., login, signup).
	AuthLimit *Limit

	// UpdateLimit defines rate limits for account update routes (e.g., email, username, password).
	UpdateLimit *Limit
}

// Route defines an API route for the authentication system.
type Route struct {
	// Method specifies the HTTP method (GET, POST, etc.).
	Method string

	// Path specifies the API path for the route.
	Path string

	// Handler specifies the handler function for the route.
	Handler string

	// Description provides a description of what the route does.
	Description string
}

// Oauth defines the configuration required for third-party OAuth integrations.
type Oauth struct {
	// ClientID is the OAuth client ID provided by the third-party service.
	ClientID string `validate:"required"`

	// ClientSecret is the OAuth client secret provided by the third-party service.
	ClientSecret string `validate:"required"`

	// CallBackURL is the endpoint where the provider will send the exchange code.
	CallBackURL string `validate:"required"`
}

// OauthConfig defines OAuth configurations for multiple providers.
type OauthConfig struct {
	// Domain specifies the domain for OAuth authentication.
	Domain string `validate:"required"`

	// Github holds the OAuth configuration for GitHub.
	Github *Oauth

	// Google holds the OAuth configuration for Google.
	Google *Oauth
}

// GauthConfig contains the main configuration settings for the authentication system.
type GauthConfig struct {
	// Database holds the configuration for user authentication via a database.
	Database *Database `validate:"required"`

	// JwtConfig holds JWT settings for token issuance and validation.
	JwtConfig *JwtConfig `validate:"required"`

	// OauthConfig holds OAuth configuration for third-party authentication providers (optional).
	OauthConfig *OauthConfig

	// EmailAndPassword enables or disables email/password authentication.
	EmailAndPassword bool

	// EmailConfig holds the configuration for email verification (optional).
	EmailConfig *EmailConfig

	// Cookie holds optional session cookie settings.
	Cookie *http.Cookie

	// Webhook holds optional webhook settings for event notifications.
	Webhook *WebhookConfig

	// RateLimitConfig holds optional rate limit configuration for certain routes.
	RateLimitConfig *RateLimitConfig

	// Fingerprinting enables login alerts for new devices.
	Fingerprinting bool

	// Logger holds the logger instance for monitoring and debugging.
	Logger logger.GauthLogger

	// routes holds the internal list of API routes.
	routes []Route
}
