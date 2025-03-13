package plainauth

import (
	"net/http"
	"sync"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

var profileImageRequestPool = &sync.Pool{
	New: func() any {
		return &ProfileImageRequest{}
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

func (s *PlainAuthAPI) GetProfileImage(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	useridStr := r.Header.Get("X-GAUTH-USERID")
	uid, err := uuid.Parse(useridStr)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusUnauthorized, "missing or invalid session")
		return
	}

	image, err := s.AuthCore.GetImage(r.Context(), uid)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusBadRequest, "failed to upload image: "+err.Error())
		return
	}

	if err := json.NewEncoder(w).Encode(ProfileImageResponse{Base64Image: image}); err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, "failed to encode image: "+err.Error())
		return
	}
}
