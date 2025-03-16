package plainauth

import (
	"net/http"
	"sync"

	"github.com/google/uuid"
	coreplainauth "github.com/scott-mescudi/gauth/core"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

var profileImageRequestPool = &sync.Pool{
	New: func() any {
		return &ProfileImageRequest{}
	},
}

var UserSessionDetailsResponse = &sync.Pool{
	New: func() any {
		return &coreplainauth.UserSessionDetails{}
	},
}

func (s *PlainAuthAPI) UploadProfileImage(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	var info = profileImageRequestPool.Get().(*ProfileImageRequest)
	defer profileImageRequestPool.Put(info)
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		errs.ErrorWithJson(w, http.StatusUnprocessableEntity, "failed to decode json")
		return
	}

	err = s.AuthCore.UploadImage(r.Context(), uid, info.Base64Image)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, "failed to upload image: "+err.Error())
		return
	}
}

func (s *PlainAuthAPI) GetUserDetails(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	var info = UserSessionDetailsResponse.Get().(*coreplainauth.UserSessionDetails)
	defer UserSessionDetailsResponse.Put(info)

	err = s.AuthCore.GetUserDetails(r.Context(), uid, info)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to get user details: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to encode user details: "+err.Error())
		return
	}
}
