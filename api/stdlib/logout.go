package plainauth

import (
	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"net/http"
)

func (s *PlainAuthAPI) Logout(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	err = s.AuthCore.LogoutHandler(r.Context(), uid)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to logout user")
		return
	}
}
