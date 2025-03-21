package plainauth

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

// VerifiedUpdatePassword initiates a secure password change with verification
// This starts a two-step process to ensure account security:
// 1. Validates old password and initiates change
// 2. Requires email verification to complete change
// Authorization: Requires a valid JWT token in the Authorization header
// The auth middleware will extract the user ID from the JWT and set X-GAUTH-USERID
// Expects JSON input:
//
//	{
//	  "old_password": "string", // Current password for verification
//	  "new_password": "string"  // New password to set after verification
//	}
//
// On success, sends verification email to user's email address
func (s *PlainAuthAPI) VerifiedUpdatePassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	var info updatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "Failed to decode string")
		return
	}

	err = s.AuthCore.VerifiedUpdatePassword(r.Context(), uid, info.OldPassword, info.NewPassword)
	if err != nil {
		if errors.Is(err, errs.ErrDuplicateKey) {
			errs.ErrorWithJson(w, http.StatusConflict, err.Error())
			return
		}

		errs.ErrorWithJson(w, http.StatusBadRequest, err.Error())
		return
	}
}

// VerifyUpdatePassword verifies a password update request using a token
// Expects query parameter: ?token=string
// Redirects to configured success URL on completion
func (s *PlainAuthAPI) VerifyUpdatePassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "missing verification token")
		return
	}

	err := s.AuthCore.VerifyUpdatePassword(r.Context(), token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "invalid token")
		return
	}

	http.Redirect(w, r, s.RedirectConfig.PasswordSet, http.StatusPermanentRedirect)
}

// HandleRecoverPassword initiates the password recovery flow
// No authorization required - used for forgotten passwords
// Sends a recovery email with a secure reset link
// Rate limited to prevent abuse
// Expects JSON input:
//
//	{
//	  "email": "string" // Account email address
//	}
//
// Always returns success to prevent email enumeration
func (s *PlainAuthAPI) HandleRecoverPassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var info HandleRecoverPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "Failed to decode string")
		return
	}

	err := s.AuthCore.HandleRecoverPassword(r.Context(), info.Email)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, err.Error())
		return
	}
}

// RecoverPassword completes the password recovery process
// No authorization required - uses secure one-time token
// Token must be obtained from recovery email
// Expects JSON input:
//
//	{
//	  "token": "string",       // One-time recovery token
//	  "new_password": "string" // New password to set
// 	}
func (s *PlainAuthAPI) RecoverPassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var info RecoverPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "Failed to decode string")
		return
	}

	err := s.AuthCore.RecoverPassword(r.Context(), info.Token, info.NewPassword)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, err.Error())
		return
	}
}
