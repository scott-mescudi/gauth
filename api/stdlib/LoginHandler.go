package plainauth

import (
	"fmt"
	"net/http"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/scott-mescudi/gauth/pkg"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

var loginPool = &sync.Pool{
	New: func() any {
		return &loginRequest{}
	},
}

// Login handles user authentication by validating credentials and generating JWT tokens
// The function supports both cookie-based and token-based authentication flows
// On successful authentication, it generates an access token and refresh token pair
// For cookie-based auth, the refresh token is set in an HTTP-only cookie
// Expects JSON input:
//
//	{
//	  "identifier": "string", // username or email
//	  "password": "string"
//	}
//
// Returns JSON:
// With cookies enabled:
//
//	{
//	  "access_token": "string" // JWT token to be used in Authorization: Bearer header
//	}
//
// Without cookies:
//
//	{
//	  "access_token": "string",  // JWT token to be used in Authorization: Bearer header
//	  "refresh_token": "string"  // Token used to obtain new access tokens
//	}
func (s *PlainAuthAPI) Login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	var info = loginPool.Get().(*loginRequest)
	defer loginPool.Put(info)
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	var fingerprint string = ""
	if s.Fingerprinting {
		fingerprint = pkg.GenerateFingerprint(r)
	}

	at, rt, err := s.AuthCore.LoginHandler(r.Context(), info.Identifier, info.Password, fingerprint)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, fmt.Sprintf("Failed to login user: %v", err))
		return
	}

	if s.Cookie != nil {
		s.Cookie.Value = rt
		http.SetCookie(w, s.Cookie)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(loginCookieResponse{AccessToken: at}); err != nil {
			errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to process response")
			return
		}
	} else {
		resp := loginResponse{AccessToken: at, RefreshToken: rt}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to process response")
			return
		}
	}
}
