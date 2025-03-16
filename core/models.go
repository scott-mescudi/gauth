package coreplainauth

import (
	"time"

	"github.com/google/uuid"
	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/auth"
	"github.com/scott-mescudi/gauth/shared/email"
	"github.com/scott-mescudi/gauth/shared/logger"
)

type Coreplainauth struct {
	DB                     database.DB
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	EmailProvider          email.EmailProvider // optional
	WebhookConfig          *WebhookConfig      // optional
	JWTConfig              *auth.JWTConfig
	EmailTemplateConfig    *EmailTemplateConfig // optional
	Logger                 logger.GauthLogger   // optional
	Domain                 string               // optional
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
	SignupTemplate              string
	UpdatePasswordTemplate      string
	UpdateEmailTemplate         string
	CancelUpdateEmailTemplate   string
	DeleteAccountTemplate       string
	CancelDeleteAccountTemplate string
}

type UserSessionDetails struct {
	ID             uuid.UUID `json:"id"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	FirstName      string    `json:"first_name"`
	LastName       string    `json:"last_name"`
	ProfilePicture string    `json:"profile_picture"`
	Role           string    `json:"role"`
	SignupMethod   string    `json:"signup_method"`
	Created        time.Time `json:"created"`
	LastLogin      time.Time `json:"last_login"`
}
