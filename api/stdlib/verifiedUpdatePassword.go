package plainauth

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

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
