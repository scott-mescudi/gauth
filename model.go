package gauth

import (
	"net/http"
	"time"

	"github.com/scott-mescudi/gauth/shared/email"
	"github.com/scott-mescudi/gauth/shared/logger"
)

// PoolConfig defines the configuration for database connection pooling.
type PoolConfig struct {
	MaxConns        int           `validate:"gte=1"` // Maximum number of database connections allowed.
	MinConns        int           `validate:"gte=0"` // Minimum number of database connections maintained in the pool.
	MaxConnLifetime time.Duration `validate:"gte=0"` // Maximum lifespan of a database connection before it is closed.
	MaxConnIdleTime time.Duration `validate:"gte=0"` // Maximum idle time before a connection is closed.
}

// Database holds the configuration required to connect to a database.
type Database struct {
	Driver string      `validate:"required"` // The database driver (e.g., "mysql", "postgres", "sqlite", "mongodb").
	Dsn    string      `validate:"required"` // The Data Source Name (DSN) for database connection.
	Config *PoolConfig // Optional configuration for managing connection pooling.
}

// JwtConfig defines settings for JSON Web Token (JWT) authentication.
type JwtConfig struct {
	Issuer                 string        `validate:"required"`      // The entity that issues the JWT.
	Secret                 []byte        `validate:"required"`      // The secret key used for signing JWTs.
	AccessTokenExpiration  time.Duration `validate:"required,gt=0"` // Expiration duration for access tokens.
	RefreshTokenExpiration time.Duration `validate:"required,gt=0"` // Expiration duration for refresh tokens.
}

// EmailTemplateConfig defines customizable email templates for various authentication flows.
type EmailTemplateConfig struct {
	SignupTemplate            string `validate:"required"` // Template used for user signup verification.
	UpdatePasswordTemplate    string `validate:"required"` // Template used for password update requests.
	UpdateEmailTemplate       string `validate:"required"` // Template for updating user email addresses.
	CancelUpdateEmailTemplate string `validate:"required"` // Template for canceling an email update request.
	DeleteAccountTemplate     string `validate:"required"` // Template for account deletion confirmation.
	LoginTemplate             string `validate:"required"` // Template used for login-related emails.
}

// WebhookConfig defines settings for integrating webhooks to receive authentication-related events.
type WebhookConfig struct {
	CallbackURL     string `validate:"required,url"`            // URL where webhook events should be sent.
	Method          string `validate:"required,oneof=POST GET"` // HTTP method used for webhook requests (e.g., POST, GET).
	AuthHeader      string // Header key for webhook authentication.
	AuthHeaderValue string // Value for the authentication header.
}

// EmailConfig holds the configuration required for email-based authentication and verification.
type EmailConfig struct {
	Provider       email.EmailProvider  `validate:"required"` // The email service provider.
	AppDomain      string               `validate:"required"` // Domain name of the application sending emails.
	TemplateConfig *EmailTemplateConfig `validate:"required"` // Email templates for authentication flows.
	RedirectConfig *RedirectConfig      `validate:"required"` // Redirect settings after email verification.
}

// RedirectConfig defines redirection URLs after completing authentication steps.
type RedirectConfig struct {
	SignupComplete string `validate:"required,url"` // URL to redirect users after signup verification.
	EmailSet       string `validate:"required,url"` // URL to redirect users after setting their email.
	PasswordSet    string `validate:"required,url"` // URL to redirect users after updating their password.
	UsernameSet    string `validate:"required,url"` // URL to redirect users after setting their username.
}

type Limit struct {
	TokenCount      int           `validate:"gte=1"` // Number of tokens a user has before hitting the limit
	CooldownPeriod  time.Duration `validate:"gte=0"` // Duration a user must wait after using all tokens
	TimeInactive    time.Duration `validate:"gte=0"`
	CleanupInterval time.Duration `validate:"gte=0"`
}

type RateLimitConfig struct {
	AuthLimit   *Limit // Rate limit for authentication routes (login, signup)
	UpdateLimit *Limit // Rate limit for account update routes (email, username, password)
}

type Route struct {
	Method  string
	Path    string
	Handler string
}

// GauthConfig contains the main configuration settings for the authentication system.
type GauthConfig struct {
	Database         *Database          `validate:"required"` // Database configuration for user authentication. Required
	JwtConfig        *JwtConfig         `validate:"required"` // JWT settings for token issuance and validation. Required
	EmailAndPassword bool               // Enables or disables email/password authentication.
	EmailConfig      *EmailConfig       // Optional email configuration for verification emails.
	Cookie           *http.Cookie       // Optional configuration for session cookies.
	Webhook          *WebhookConfig     // Optional webhook settings for event notifications.
	RateLimitConfig  *RateLimitConfig   // optional ratelimit config for certain routes
	Fingerprinting   bool               // Enables user login alerts for new devices.
	Logger           logger.GauthLogger // Logger instance for monitoring and debugging.
	routes           []Route            // Internal list of API routes.
}
