package plainauth

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

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

	http.Redirect(w, r, s.RedirectURL+"/login", http.StatusPermanentRedirect)
}
