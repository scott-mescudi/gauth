package plainauth

import (
	"net/http"

	auth "github.com/scott-mescudi/gauth/core/plain_auth"
)

type PlainAuthAPI struct {
	AuthCore       *auth.Coreplainauth
	Cookie         *http.Cookie
	Fingerprinting bool
	RedirectConfig *RedirectConfig
}

type RedirectConfig struct {
	SignupComplete string
	EmailSet       string
	PasswordSet    string
	UsernameSet    string
}

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type loginCookieResponse struct {
	AccessToken string `json:"access_token"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type signupRequest struct {
	Fname    string `json:"first_name"` // optional
	Lname    string `json:"last_name"`  // optional
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type updateEmailRequest struct {
	NewEmail string `json:"new_email"`
}

type updateUsernameRequest struct {
	NewUsername string `json:"new_username"`
}

type updatePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type Fingerprint struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

type ProfileImageRequest struct {
	Base64Image string `json:"base64Image"`
}

type ProfileImageResponse struct {
	Base64Image string `json:"base64Image"`
}
