package plainauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

func (s *PlainAuthAPI) VerifiedUpdatePassword(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	uidstr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(uidstr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "invalid or missing userid header")
		return
	}

	var info updatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	if err := s.AuthCore.VerifiedUpdatePasswordHandler(r.Context(), uid, info.OldPassword, info.NewPassword); err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, err.Error())
		return
	}
}

func (s *PlainAuthAPI) VerifiedUpdateEmail(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	uidstr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(uidstr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "invalid or missing userid header")
		return
	}

	var info updateEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	if err := s.AuthCore.VerifiedUpdateEmailHandler(r.Context(), uid, info.NewEmail); err != nil {
		if errors.Is(err, errs.ErrDuplicateKey) {
			errs.ErrorWithJson(w, http.StatusConflict, "user with that email already exists")
			return
		}

		if errors.Is(err, errs.ErrNoChange) {
			errs.ErrorWithJson(w, http.StatusConflict, "new email cannot be the same as old email")
			return
		}

		errs.ErrorWithJson(w, http.StatusBadRequest, err.Error())
		return
	}
}

func (s *PlainAuthAPI) VerifiedUpdateUsername(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	uidstr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(uidstr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "invalid or missing userid header")
		return
	}

	var info updateUsernameRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	if err := s.AuthCore.VerifiedUpdateUsernameHandler(r.Context(), uid, info.NewUsername); err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, err.Error())
		return
	}
}

func (s *PlainAuthAPI) VerifyUpdatePassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	err := s.AuthCore.VerifyUpdatePasswordToken(r.Context(),  token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, fmt.Sprintf("Failed to verify token: %v", err))
		return
	}

	http.Redirect(w, r, s.RedirectURL, http.StatusTemporaryRedirect)
}

func (s *PlainAuthAPI) VerifyUpdateUsername(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	err := s.AuthCore.VerifyUpdateUsernameToken(r.Context(),  token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, fmt.Sprintf("Failed to verify token: %v", err))
		return
	}

	http.Redirect(w, r, s.RedirectURL, http.StatusTemporaryRedirect)
}

func (s *PlainAuthAPI) VerifyUpdateEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	err := s.AuthCore.VerifyUpdateEmailToken(r.Context(),  token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, fmt.Sprintf("Failed to verify token: %v", err))
		return
	}

	http.Redirect(w, r, s.RedirectURL, http.StatusTemporaryRedirect)
}