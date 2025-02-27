package plainauth

import (
	"net/http"
	auth "github.com/scott-mescudi/gauth/core/plain_auth"
	"github.com/scott-mescudi/gauth/database"
)

type PlainAuthAPI struct {
	Db       database.DB
	AuthCore *auth.Coreplainauth
	cookie   *http.Cookie
}


type LoginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
