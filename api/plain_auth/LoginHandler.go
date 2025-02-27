package plainauth

import (
	"net/http"
	"sync"

	jsoniter "github.com/json-iterator/go"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

var loginPool = &sync.Pool{
	New: func() any {
		return &LoginRequest{}
	},
}

func (s *PlainAuthAPI) Login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	var info = loginPool.Get().(*LoginRequest)
	defer loginPool.Put(info)
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	if info.Identifier == "" || info.Password == "" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "identifier or password cannot be empty")
		return
	}

	at, rt, err := s.AuthCore.LoginHandler(info.Identifier, info.Password)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, err.Error())
		return
	}

	if s.cookie != nil {
		s.cookie.Value = rt
		http.SetCookie(w, s.cookie)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"access_token": at}); err != nil {
			errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to process response")
			return
		}
	} else {
		resp := LoginResponse{AccessToken: at, RefreshToken: rt}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to process response")
			return
		}
	}
}
