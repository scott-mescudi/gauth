package plainauth

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	errs "github.com/scott-mescudi/gauth/shared/errors"
)

var signupPool = &sync.Pool{
	New: func() any {
		return &signupRequest{}
	},
}

func (s *PlainAuthAPI) Signup(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	var info = signupPool.Get().(*signupRequest)
	defer signupPool.Put(info)
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	if info.Username == "" || info.Password == "" || info.Email == "" || info.Role == "" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "Not all fields are included")
		return
	}

	err := s.AuthCore.SignupHandler(info.Username, info.Email, info.Password, info.Role)
	if err != nil {
		if errors.Is(err, errs.ErrDuplicateKey) {
			errs.ErrorWithJson(w, http.StatusConflict, "User already exists")
			return
		}
		errs.ErrorWithJson(w, http.StatusBadRequest, fmt.Sprintf("Failed to create user: %v", err))
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (s *PlainAuthAPI) VerifiedSignup(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	if r.Header.Get("Content-Type") != "application/json" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "wrong content type header")
		return
	}

	var info = signupPool.Get().(*signupRequest)
	defer signupPool.Put(info)
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to process request body")
		return
	}

	if info.Username == "" || info.Password == "" || info.Email == "" || info.Role == "" {
		errs.ErrorWithJson(w, http.StatusBadRequest, "Not all fields are included")
		return
	}

	err := s.AuthCore.SignupHandlerWithEmailVerification(info.Username, info.Email, info.Password, info.Role)
	if err != nil {
		if errors.Is(err, errs.ErrDuplicateKey) {
			errs.ErrorWithJson(w, http.StatusConflict, "User already exists")
			return
		}
		errs.ErrorWithJson(w, http.StatusBadRequest, fmt.Sprintf("Failed to create user: %v", err))
		return
	}
}

func (s *PlainAuthAPI) VerifySignup(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	err := s.AuthCore.VerifySignupToken(token)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, fmt.Sprintf("Failed to verify token: %v", err))
		return
	}

	http.Redirect(w, r, s.RedirectURL, http.StatusTemporaryRedirect)
}
