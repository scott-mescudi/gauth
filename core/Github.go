package coreplainauth

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/scott-mescudi/gauth/shared/variables"
)

func (s *Coreplainauth) GithubOauthLogin(ctx context.Context, username string) (accessToken, refreshToken string, err error) {
	s.logInfo("Github OAuth login attempt for user: %s", username)

	uid, _, err := s.DB.GetUserPasswordAndIDByUsername(ctx, username)
	if err != nil {
		s.logError("Error retrieving user ID for username %s: %v", username, err)
		return "", "", err
	}

	accessToken, err = s.JWTConfig.GenerateHMac(uid, variables.ACCESS_TOKEN, time.Now().Add(s.AccessTokenExpiration))
	if err != nil {
		s.logError("Error generating access token for user %s: %v", uid, err)
		return "", "", err
	}

	refreshToken, err = s.JWTConfig.GenerateHMac(uid, variables.REFRESH_TOKEN, time.Now().Add(s.RefreshTokenExpiration))
	if err != nil {
		s.logError("Error generating refresh token for user %s: %v", uid, err)
		return "", "", err
	}

	s.logInfo("Github OAuth login successful for user: %s", username)
	return accessToken, refreshToken, nil
}

func (s *Coreplainauth) GithubOauthSignup(ctx context.Context, avatarURL, email, username string) (accessToken, refreshToken string, err error) {
	s.logInfo("Github OAuth signup attempt for user: %s", username)

	uid, err := s.DB.AddUser(ctx, "", "", username, email, "user", "", true)
	if err != nil {
		s.logError("Error adding new user %s: %v", username, err)
		return "", "", err
	}

	err = s.DB.SetSignupMethod(ctx, uid, "github")
	if err != nil {
		s.logError("Error setting signup method for user %s: %v", uid, err)
		return "", "", err
	}

	if avatarURL != "" {
		go func() {
			s.logInfo("Fetching avatar image for user: %s", username)
			resp, err := http.Get(avatarURL)
			if err != nil {
				s.logError("Error fetching image for user %s: %v", username, err)
				return
			}
			defer resp.Body.Close()

			imageData, err := io.ReadAll(resp.Body)
			if err != nil {
				s.logError("Error reading image data for user %s: %v", username, err)
				return
			}

			encoded := base64.StdEncoding.EncodeToString(imageData)
			err = s.DB.SetUserImage(context.Background(), uid, []byte(encoded))
			if err != nil {
				s.logError("failed to store avatar for user %s: %v", username, err)
			}

			s.logInfo("Avatar image successfully stored for user: %s", username)
		}()
	}

	accessToken, err = s.JWTConfig.GenerateHMac(uid, variables.ACCESS_TOKEN, time.Now().Add(s.AccessTokenExpiration))
	if err != nil {
		s.logError("Error generating access token for user %s: %v", uid, err)
		return "", "", err
	}

	refreshToken, err = s.JWTConfig.GenerateHMac(uid, variables.REFRESH_TOKEN, time.Now().Add(s.RefreshTokenExpiration))
	if err != nil {
		s.logError("Error generating refresh token for user %s: %v", uid, err)
		return "", "", err
	}

	s.logInfo("Github OAuth signup successful for user: %s", username)
	return accessToken, refreshToken, nil
}

func (s *Coreplainauth) HandleGithubOauth(ctx context.Context, avatarURL, email, username string) (accessToken, refreshToken string, err error) {
	s.logInfo("Handling Github OAuth for identifier: %s", username)

	if s.DB.UserExists(ctx, username) {
		s.logInfo("User %s exists, proceeding with login.", username)
		return s.GithubOauthLogin(ctx, username)
	}

	s.logInfo("User %s does not exist, proceeding with signup.", username)
	return s.GithubOauthSignup(ctx, avatarURL, email, username)
}
