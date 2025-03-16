package plainauth

import (
	"net/http"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

func (s *PlainAuthAPI) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	err = s.AuthCore.DeleteAccount(r.Context(), uid)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to delete account")
		return
	}
}

func (s *PlainAuthAPI) VerifiedDeleteAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	err = s.AuthCore.VerifiedDeleteAccount(r.Context(), uid)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to delete account")
		return
	}
}

func (s *PlainAuthAPI) VerifyDeleteAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	token := r.URL.Query().Get("token")
	if token == "" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "missing verification token")
		return
	}

	err := s.AuthCore.VerifyDeleteAccount(r.Context(), token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to delete account")
		return
	}

	http.Redirect(w, r, s.AuthCore.Domain, http.StatusPermanentRedirect)
}

func (s *PlainAuthAPI) CancelDeleteAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	token := r.URL.Query().Get("token")
	if token == "" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "missing verification token")
		return
	}

	err := s.AuthCore.CancelDeleteAccount(r.Context(), token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to cancel delete account")
		return
	}

	http.Redirect(w, r, s.AuthCore.Domain, http.StatusPermanentRedirect)
}
