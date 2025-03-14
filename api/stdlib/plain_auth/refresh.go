package plainauth

import (
	errs "github.com/scott-mescudi/gauth/shared/errors"

	"net/http"
)

func (s *PlainAuthAPI) Refresh(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var info RefreshRequest
	if s.Cookie != nil {
		cookie, err := r.Cookie(s.Cookie.Name)
		if err != nil {
			errs.ErrorWithJson(w, http.StatusNotFound, "missing refresh cookie")
			return
		}

		info.RefreshToken = cookie.Value
	} else {
		if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
			errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "invalid request payload")
			return
		}
	}

	at, rt, err := s.AuthCore.RefreshHandler(r.Context(), info.RefreshToken)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}

	if s.Cookie != nil {
		s.Cookie.Value = rt
		http.SetCookie(w, s.Cookie)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(loginCookieResponse{AccessToken: at}); err != nil {
			errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to process response")
			return
		}
	} else {
		resp := loginResponse{AccessToken: at, RefreshToken: rt}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to process response")
			return
		}
	}
}
