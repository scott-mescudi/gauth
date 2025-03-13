package coreplainauth

import (
	"io"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/auth"
	"github.com/scott-mescudi/gauth/shared/email"
)

type Coreplainauth struct {
	DB                     database.DB
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	EmailProvider          email.EmailProvider
	WebhookConfig          *WebhookConfig
	JWTConfig              *auth.JWTConfig
	EmailTemplateConfig    *EmailTemplateConfig
	LoggingOutput          io.Writer
	Domain                 string
}

type WebhookConfig struct {
	CallbackURL     string
	Method          string
	AuthHeader      string
	AuthHeaderValue string
}

type WebhookRequest struct {
	Identifier string `json:"idenitfier"`
	Message    string `json:"message"`
}

type EmailTemplateConfig struct {
	SignupTemplate            string
	UpdatePasswordTemplate    string
	UpdateEmailTemplate       string
	CancelUpdateEmailTemplate string
	DeleteAccountTemplate     string
	LoginTemplate             string
}
