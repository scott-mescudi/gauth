package plainauth

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

// VerifiedUpdateEmail initiates a secure email update process with verification
// This starts a two-step process:
// 1. User requests email change
// 2. User verifies new email via email link
// Authorization: Requires a valid JWT token in the Authorization header
// The auth middleware will extract the user ID from the JWT and set X-GAUTH-USERID
// Expects JSON input:
//
//	{
//	  "new_email": "string" // New email address to verify
//	}
//
// On success, sends verification email to new address
func (s *PlainAuthAPI) VerifiedUpdateEmail(w http.ResponseWriter, r *http.Request) {
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

	err = s.AuthCore.VerifiedUpdateEmail(r.Context(), uid, UpdateEmail.NewEmail)
	if err != nil {
		if errors.Is(err, errs.ErrDuplicateKey) {
			errs.ErrorWithJson(w, http.StatusConflict, err.Error())
			return
		}

		errs.ErrorWithJson(w, http.StatusBadRequest, err.Error())
		return
	}
}

// VerifyUpdateEmail completes the email verification process
// Called when user clicks verification link in email
// No authorization required as verification is handled via secure token
// Expects query parameter: ?token=string
// On success redirects to configured email update success page
func (s *PlainAuthAPI) VerifyUpdateEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "missing verification token")
		return
	}

	err := s.AuthCore.VerifyUpdateEmail(r.Context(), token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "invalid token")
		return
	}

	http.Redirect(w, r, s.RedirectConfig.EmailSet, http.StatusPermanentRedirect)
}

// CancelUpdateEmail cancels a pending email update request
// Called when user clicks cancellation link in email
// No authorization required as cancellation is handled via secure token
// Expects query parameter: ?token=string
// On success redirects to application home page
func (s *PlainAuthAPI) CancelUpdateEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "missing verification token")
		return
	}

	err := s.AuthCore.CancelVerifyUpdateEmail(r.Context(), token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "invalid token")
		return
	}

	http.Redirect(w, r, s.AuthCore.Domain, http.StatusPermanentRedirect)
}
