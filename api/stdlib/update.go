package plainauth

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

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
