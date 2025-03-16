package plainauth

import (
	"context"
	"net/http"

	errs "github.com/scott-mescudi/gauth/shared/errors"
	"golang.org/x/oauth2"
)

func (s *PlainAuthAPI) HandleGithubLogin(w http.ResponseWriter, r *http.Request) {
	url := s.OauthConfig.Github.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *PlainAuthAPI) GithubOauthCallback(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code found", http.StatusBadRequest)
		return
	}

	token, err := s.OauthConfig.Github.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to get token", http.StatusInternalServerError)
		return
	}

	client := s.OauthConfig.Github.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var user GithubUserDetails
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		return
	}

	at, rt, err := s.AuthCore.HandleGithubOauth(r.Context(), user.AvatarURL, user.Email, user.Login)
	if err != nil {
		errs.ErrorWithJson(w, http.StatusInternalServerError, err.Error())
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
