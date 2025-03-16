package coreplainauth

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/scott-mescudi/gauth/shared/variables"
)

func (s *Coreplainauth) GoogleOauthLogin(ctx context.Context, email string) (accessToken, refreshToken string, err error) {
	s.logInfo("Google OAuth login attempt for user: %s", email)

	uid, _, err := s.DB.GetUserPasswordAndIDByEmail(ctx, email)
	if err != nil {
		s.logError("Error retrieving user ID for email %s: %v", email, err)
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

	s.logInfo("Google OAuth login successful for user: %s", email)
	return accessToken, refreshToken, nil
}

func (s *Coreplainauth) GoogleOauthSignup(ctx context.Context, avatarURL, email, username string) (accessToken, refreshToken string, err error) {
	s.logInfo("Google OAuth signup attempt for user: %s", email)

	uid, err := s.DB.AddUser(ctx, "", "", username, email, "user", "", true)
	if err != nil {
		s.logError("Error adding new user %s: %v", email, err)
		return "", "", err
	}

	err = s.DB.SetSignupMethod(ctx, uid, "google")
	if err != nil {
		s.logError("Error setting signup method for user %s: %v", uid, err)
		return "", "", err
	}

	if avatarURL != "" {
		go func() {
			s.logInfo("Fetching avatar image for user: %s", email)
			resp, err := http.Get(avatarURL)
			if err != nil {
				s.logError("Error fetching image for user %s: %v", email, err)
				return
			}
			defer resp.Body.Close()

			imageData, err := io.ReadAll(resp.Body)
			if err != nil {
				s.logError("Error reading image data for user %s: %v", email, err)
				return
			}

			encoded := base64.StdEncoding.EncodeToString(imageData)
			err = s.DB.SetUserImage(context.Background(), uid, []byte(encoded))
			if err != nil {
				s.logError("failed to store avatar for user %s: %v", email, err)
			}

			s.logInfo("Avatar image successfully stored for user: %s", email)
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

	s.logInfo("Google OAuth signup successful for user: %s", email)
	return accessToken, refreshToken, nil
}

func (s *Coreplainauth) HandleGoogleOauth(ctx context.Context, avatarURL, username, email string) (accessToken, refreshToken string, err error) {
	s.logInfo("Handling Google OAuth for identifier: %s", email)

	if s.DB.UserExistsByEmail(ctx, email) {
		s.logInfo("User %s exists, proceeding with login.", email)
		return s.GoogleOauthLogin(ctx, email)
	}

	s.logInfo("User %s does not exist, proceeding with signup.", email)
	return s.GoogleOauthSignup(ctx, avatarURL, email, username)
}
