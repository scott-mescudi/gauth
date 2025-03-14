package gauth

import (
	"github.com/scott-mescudi/gauth/shared/logger"
	"net/http"
	"time"
)

type PoolConfig struct {
	MaxConns        int           // The maximum number of database connections allowed. This is a required field.
	MinConns        int           // The minimum number of database connections maintained in the pool. This is a required field.
	MaxConnLifetime time.Duration // The maximum amount of time a connection can live before being closed. This is a required field.
	MaxConnIdleTime time.Duration // The maximum amount of time a connection can remain idle before being closed. This is a required field.
}

type Database struct {
	Driver string      // The database driver to use (e.g., "mysql", "postgres", "sqlite", "mongodb"). This is a required field.
	Dsn    string      // The Data Source Name (DSN) used to connect to the database. This is a required field.
	Config *PoolConfig // Optional connection pool configuration for managing database connections.
}

type JwtConfig struct {
	Issuer                 string
	Secret                 []byte
	AccessTokenExpiration  time.Duration // The expiration time for access tokens. This is a required field.
	RefreshTokenExpiration time.Duration // The expiration time for refresh tokens. This is a required field.
}

type EmailTemplateConfig struct {
	SignupTemplate            string
	UpdatePasswordTemplate    string
	UpdateEmailTemplate       string
	CancelUpdateEmailTemplate string
	DeleteAccountTemplate     string
	LoginTemplate             string
}

type WebhookConfig struct {
	CallbackURL     string
	Method          string
	AuthHeader      string
	AuthHeaderValue string
}

type EmailConfig struct {
	Provider                     string
	FromName                     string // The name displayed as the sender of the email. This is a required field.
	FromEmail                    string // The email address used as the sender. This is a required field.
	ApiKey                       string // The API key used to authenticate with the email service provider. This is a required field.
	AppDomain                    string // The domain name of the application sending the email. This is a required field.
	TemplateConfig               *EmailTemplateConfig
}

type GauthConfig struct {
	Database         *Database // The database configuration for user storage. This is a required field.
	JwtConfig        *JwtConfig
	EmailAndPassword bool         // Flag indicating whether email/password authentication is enabled. This is a required field.
	EmailConfig      *EmailConfig // Optional email configuration for sending verification emails.
	Cookie           *http.Cookie // Optional HTTP cookie configuration for session management.
	Webhook          *WebhookConfig
	Fingerprinting   bool
	Logger           logger.GauthLogger
}
