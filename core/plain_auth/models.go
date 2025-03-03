package coreplainauth

import (
	"io"
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/email"
)

type Coreplainauth struct {
	DB                     database.DB
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	EmailProvider          *email.TwilioConfig
	WebhookConfig 			*WebhookConfig
	LoggingOutput 			io.Writer
	Domain                 string
}

type WebhookConfig struct {
	CallbackURL     string
	Method string
	AuthHeader      string
	AuthHeaderValue string
}