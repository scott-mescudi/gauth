package plainauth

import (
	"net/http"

	auth "github.com/scott-mescudi/gauth/core/plain_auth"
)

type PlainAuthAPI struct {
	AuthCore *auth.Coreplainauth
	Cookie   *http.Cookie
	RedirectURL string
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
