package plainauth

import (
	"net/http"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

// DeleteAccount handles the deletion of a user account.
// Requires 'X-GAUTH-USERID' set by middleware, and an 'Authorization' header with a valid JWT token.
func (s *PlainAuthAPI) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Retrieve and parse the user ID from the header
	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		// Return error if the user ID is missing or invalid
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	// Attempt to delete the account and handle any errors
	err = s.AuthCore.DeleteAccount(r.Context(), uid)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to delete account")
		return
	}
}

// VerifiedDeleteAccount handles the deletion of a user account that requires email verification.
// Requires 'X-GAUTH-USERID' set by middleware, and an 'Authorization' header with a valid JWT token.
func (s *PlainAuthAPI) VerifiedDeleteAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Retrieve and parse the user ID from the header
	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		// Return error if the user ID is missing or invalid
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	// Attempt to initiate the verified account deletion process
	err = s.AuthCore.VerifiedDeleteAccount(r.Context(), uid)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to delete account")
		return
	}
}

// VerifyDeleteAccount handles the callback after the user clicks on the verification link sent by VerifiedDeleteAccount.
// Expects a 'token' query parameter for user verification.
func (s *PlainAuthAPI) VerifyDeleteAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Retrieve the verification token from the query parameters
	token := r.URL.Query().Get("token")
	if token == "" {
		// Return error if the token is missing
		errs.ErrorWithJson(w, http.StatusBadRequest, "missing verification token")
		return
	}

	// Attempt to verify the delete account request with the provided token
	err := s.AuthCore.VerifyDeleteAccount(r.Context(), token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to delete account")
		return
	}

	// Redirect the user to the main domain after successful deletion verification
	http.Redirect(w, r, s.AuthCore.Domain, http.StatusPermanentRedirect)
}

// CancelDeleteAccount handles the callback after the user clicks on the cancellation link sent by VerifiedDeleteAccount.
// Expects a 'token' query parameter for cancellation.
func (s *PlainAuthAPI) CancelDeleteAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	// Retrieve the cancellation token from the query parameters
	token := r.URL.Query().Get("token")
	if token == "" {
		// Return error if the token is missing
		errs.ErrorWithJson(w, http.StatusBadRequest, "missing verification token")
		return
	}

	// Attempt to cancel the delete account request with the provided token
	err := s.AuthCore.CancelDeleteAccount(r.Context(), token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to cancel delete account")
		return
	}

	// Redirect the user to the main domain after successful cancellation
	http.Redirect(w, r, s.AuthCore.Domain, http.StatusPermanentRedirect)
}
