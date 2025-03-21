package coreplainauth

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"time"
)

// GithubOauthLogin handles the OAuth login process for a user via GitHub.
// It attempts to log in a user by generating an access token and refresh token.
// The function first retrieves the user's ID by their username, then generates
// the access token and refresh token using the user's ID. If any errors occur during
// these steps, the function returns an error along with empty token strings.
//
// Parameters:
// - ctx: The context used for the database operations and token generation.
// - username: The username of the user attempting to log in via GitHub.
//
// Returns:
// - accessToken: A JWT access token that is generated for the user.
// - refreshToken: A JWT refresh token that is generated for the user.
// - err: An error, if any, that occurred during the login process.
func (s *Coreplainauth) GithubOauthLogin(ctx context.Context, username string) (accessToken, refreshToken string, err error) {
	s.logInfo("Github OAuth login attempt for user: %s", username)

	uid, _, err := s.DB.GetUserPasswordAndIDByUsername(ctx, username)
	if err != nil {
		s.logError("Error retrieving user ID for username %s: %v", username, err)
		return "", "", err
	}

	accessToken, refreshToken, err = s.generateTokens(uid)
	if err != nil {
		return "", "", err
	}

	s.logInfo("Github OAuth login successful for user: %s", username)
	return accessToken, refreshToken, nil
}

// GithubOauthSignup handles the OAuth signup process for a new user via GitHub.
// If the user is new, this function registers the user by creating a new user entry
// in the database and generates both access and refresh tokens. Additionally, it handles
// the user's avatar image by fetching it from the provided URL and storing it in the database.
//
// Parameters:
// - ctx: The context used for the database operations and token generation.
// - avatarURL: The URL of the user's avatar image, which is optional.
// - email: The email address of the user being registered.
// - username: The username of the new user being registered via GitHub.
//
// Returns:
// - accessToken: A JWT access token generated for the new user.
// - refreshToken: A JWT refresh token generated for the new user.
// - err: An error, if any, that occurred during the signup process.
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
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, avatarURL, nil)
			if err != nil {
				s.logError("Error fetching image for user %s: %v", username, err)
				return
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				s.logError("Failed to create HTTP request for avatar: %v", err)
				return
			}

			defer resp.Body.Close()

			imageData, err := io.ReadAll(resp.Body)
			if err != nil {
				s.logError("Error reading image data for user %s: %v", username, err)
				return
			}

			encoded := base64.StdEncoding.EncodeToString(imageData)
			err = s.DB.SetUserImage(ctx, uid, []byte(encoded))
			if err != nil {
				s.logError("failed to store avatar for user %s: %v", username, err)
			}

			s.logInfo("Avatar image successfully stored for user: %s", username)
		}()
	}

	accessToken, refreshToken, err = s.generateTokens(uid)
	if err != nil {
		return "", "", err
	}

	s.logInfo("Github OAuth signup successful for user: %s", username)
	return accessToken, refreshToken, nil
}

// HandleGithubOauth is the main entry point for handling both OAuth login and signup via GitHub.
// This function first checks if the user already exists in the database. If the user exists,
// it triggers the login process. If the user does not exist, it triggers the signup process.
// It ensures that the correct flow is followed based on the user's status.
//
// Parameters:
//   - ctx: The context used for database operations and OAuth handling.
//   - avatarURL: The URL of the user's avatar image, used if the user is signing up.
//   - email: The email address of the user, used if the user is signing up.
//   - username: The username of the user attempting to log in or sign up.
//
// Returns:
//   - accessToken: A JWT access token for the user (generated during login or signup).
//   - refreshToken: A JWT refresh token for the user (generated during login or signup).
//   - err: An error, if any, occurred during the OAuth process.
func (s *Coreplainauth) HandleGithubOauth(ctx context.Context, avatarURL, email, username string) (accessToken, refreshToken string, err error) {
	s.logInfo("Handling Github OAuth for identifier: %s", username)

	if s.DB.UserExists(ctx, username) {
		s.logInfo("User %s exists, proceeding with login.", username)
		return s.GithubOauthLogin(ctx, username)
	}

	s.logInfo("User %s does not exist, proceeding with signup.", username)
	return s.GithubOauthSignup(ctx, avatarURL, email, username)
}
