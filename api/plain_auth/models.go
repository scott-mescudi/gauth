package plainauth

import (
	auth "github.com/scott-mescudi/gauth/core/plain_auth"
	"net/http"
)

type PlainAuthAPI struct {
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
