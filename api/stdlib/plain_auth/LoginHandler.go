package plainauth

import (
	"fmt"
	"net/http"
	"sync"

	jsoniter "github.com/json-iterator/go"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

var loginPool = &sync.Pool{
	New: func() any {
		return &loginRequest{}
	},
}

func (s *PlainAuthAPI) Login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	var info = loginPool.Get().(*loginRequest)
	defer loginPool.Put(info)
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	var fingerprint string = ""
	if s.Fingerprinting {
		ifv := GetFingerprint(r)
		if ifv == nil {
			return
		}

		fingerprintBytes, err := json.Marshal(ifv)
		if err != nil {
			return
		}

		fingerprint = string(fingerprintBytes)
	}

	at, rt, err := s.AuthCore.LoginHandler(r.Context(), info.Identifier, info.Password, fingerprint)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, fmt.Sprintf("Failed to login user: %v", err))
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
