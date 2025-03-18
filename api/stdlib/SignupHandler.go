package plainauth

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

var signupPool = &sync.Pool{
	New: func() any {
		return &signupRequest{}
	},
}

// Signup creates a new user account with immediate activation
// No authorization required - public endpoint
// Use this when email verification is not required
// Expects JSON input:
//
//	{
//	  "fname": "string",     // First name, optional
//	  "lname": "string",     // Last name, optional
//	  "username": "string",  // Unique username
//	  "email": "string",     // Valid email address
//	  "password": "string",  // Password meeting policy requirements
//	  "role": "string"      // User role
//	}
//
// Returns 201 Created on success
func (s *PlainAuthAPI) Signup(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	var info = signupPool.Get().(*signupRequest)
	defer signupPool.Put(info)
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	err := s.AuthCore.SignupHandler(r.Context(), info.Fname, info.Lname, info.Username, info.Email, info.Password, info.Role, false)
	if err != nil {
		if errors.Is(err, errs.ErrDuplicateKey) {
			errs.ErrorWithJson(w, http.StatusConflict, "User already exists")
			return
		}
		errs.ErrorWithJson(w, http.StatusBadRequest, fmt.Sprintf("Failed to create user: %v", err))
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// VerifiedSignup creates a new unverified user account
// No authorization required - public endpoint
// Initiates email verification process:
//  1. Creates inactive account
//  2. Sends verification email
//  3. Requires email verification to activate
//
// Expects same JSON input as Signup
// Returns 200 OK on successful initiation
func (s *PlainAuthAPI) VerifiedSignup(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	var info = signupPool.Get().(*signupRequest)
	defer signupPool.Put(info)
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	err := s.AuthCore.SignupHandler(r.Context(), info.Fname, info.Lname, info.Username, info.Email, info.Password, info.Role, true)
	if err != nil {
		if errors.Is(err, errs.ErrDuplicateKey) {
			errs.ErrorWithJson(w, http.StatusConflict, "User already exists")
			return
		}
		errs.ErrorWithJson(w, http.StatusBadRequest, fmt.Sprintf("Failed to create user: %v", err))
		return
	}
}

// VerifySignup verifies a signup request using a token
// Expects query parameter: ?token=string
// Redirects to configured success URL on completion
func (s *PlainAuthAPI) VerifySignup(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	err := s.AuthCore.VerifySignupToken(r.Context(), token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, fmt.Sprintf("Failed to verify token: %v", err))
		return
	}

	http.Redirect(w, r, s.RedirectConfig.SignupComplete, http.StatusPermanentRedirect)
}
