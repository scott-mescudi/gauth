package plainauth

import (
	"net/http"

	jsoniter "github.com/json-iterator/go"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

func (s *PlainAuthAPI) Login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	var info LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	at, rt, err := s.AuthCore.LoginHandler(info.Identifier, info.Password)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, err.Error())
		return
	}

	resp := LoginResponse{AccessToken: at, RefreshToken: rt}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to process response")
		return
	}
}
