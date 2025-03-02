package coreplainauth

import (
	"time"

	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/email"
)

type Coreplainauth struct {
	DB                     database.DB
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	EmailProvider          *email.TwilioConfig
	Domain                 string
}