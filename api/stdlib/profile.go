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

// UploadProfileImage updates the user's profile image with a base64 encoded image
// The image should be a web-safe format (PNG, JPEG, etc)
// Authorization: Requires a valid JWT token in the Authorization header
// The auth middleware will extract the user ID from the JWT and set X-GAUTH-USERID
// Expects JSON input:
//
//	{
//	  "base64_image": "string" // Base64 encoded image data
//	}
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

// GetUserDetails retrieves the complete profile information for the authenticated user
// Authorization: Requires a valid JWT token in the Authorization header
// The auth middleware will extract the user ID from the JWT and set X-GAUTH-USERID
// Returns JSON containing all user profile fields including optional profile image
// Returns JSON:
//
//	{
//	  "user_id": "string",      // UUID of the user
//	  "username": "string",     // Current username
//	  "email": "string",        // Verified email address
//	  "fname": "string",        // First name
//	  "lname": "string",        // Last name
//	  "role": "string",         // User role (e.g. admin, user)
//	  "profile_image": "string" // Base64 encoded profile image if set
//	}
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
