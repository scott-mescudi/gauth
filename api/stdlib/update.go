package plainauth

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

// UpdateEmail immediately updates a user's email without requiring verification
// This is for systems that handle email verification separately
// Authorization: Requires a valid JWT token in the Authorization header
// The auth middleware will extract the user ID from the JWT and set X-GAUTH-USERID
// Expects JSON input:
//
//	{
//	  "new_email": "string" // New email address to set
//	}
func (s *PlainAuthAPI) UpdateEmail(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	var UpdateEmail updateEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&UpdateEmail); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "Failed to decode string")
		return
	}

	err = s.AuthCore.UpdateEmail(r.Context(), uid, UpdateEmail.NewEmail)
	if err != nil {
		if errors.Is(err, errs.ErrDuplicateKey) {
			errs.ErrorWithJson(w, http.StatusConflict, err.Error())
			return
		}

		errs.ErrorWithJson(w, http.StatusBadRequest, err.Error())
		return
	}
}

// UpdateUsername changes the user's username if the new username is available
// Authorization: Requires a valid JWT token in the Authorization header
// The auth middleware will extract the user ID from the JWT and set X-GAUTH-USERID
// Expects JSON input:
//
//	{
//	  "new_username": "string" // New username to set
//	}
//
// Returns 409 Conflict if username is already taken
func (s *PlainAuthAPI) UpdateUsername(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	var info updateUsernameRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "Failed to decode string")
		return
	}

	err = s.AuthCore.UpdateUsername(r.Context(), uid, info.NewUsername)
	if err != nil {
		if errors.Is(err, errs.ErrDuplicateKey) {
			errs.ErrorWithJson(w, http.StatusConflict, err.Error())
			return
		}

		errs.ErrorWithJson(w, http.StatusBadRequest, err.Error())
		return
	}
}

// UpdatePassword changes the user's password after validating the old password
// Authorization: Requires a valid JWT token in the Authorization header
// The auth middleware will extract the user ID from the JWT and set X-GAUTH-USERID
// This direct update does not require email verification
// Expects JSON input:
//
//	{
//	  "old_password": "string", // Current password for verification
//	  "new_password": "string"  // New password to set
//	}
func (s *PlainAuthAPI) UpdatePassword(w http.ResponseWriter, r *http.Request) {
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

	err = s.AuthCore.UpdatePassword(r.Context(), uid, info.OldPassword, info.NewPassword)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, err.Error())
		return
	}
}
