package plainauth

import (
	"time"

	"github.com/scott-mescudi/gauth/database"
)

type PlainAuth struct {
	DB database.DB
	AccessTokenExpiration time.Time
	RefreshTokenExpiration time.Time
}