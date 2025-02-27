package plainauth

import (
	auth "github.com/scott-mescudi/gauth/core/plain_auth"
	"net/http"
)

type PlainAuthAPI struct {
	AuthCore *auth.Coreplainauth
	cookie   *http.Cookie
}

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type signupRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}
