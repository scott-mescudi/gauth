package coreplainauth

import (
	"time"

	"github.com/scott-mescudi/gauth/database"
)

type Coreplainauth struct {
	DB                     database.DB
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
}
