package coreplainauth

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
	"github.com/scott-mescudi/gauth/pkg/hashing"
)

// Email regex pattern for email validation
var (
	emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re         = regexp.MustCompile(emailRegex)
)

// login attempts to authenticate a user based on the identifier (email or username) and password provided.
// If successful, it generates and returns access and refresh tokens for the user. Additionally, it checks
// if the user is verified and validates the provided password against the stored hash.
// Optionally, it handles user fingerprint checks and triggers webhooks for login notifications.
//
// Parameters:
//   - ctx: The context used for all database operations and actions.
//   - identifier: The username or email of the user attempting to log in.
//   - password: The password provided by the user to authenticate.
//   - fingerprint: A unique identifier for the user's device/browser, used for fingerprint checking. if no fingerprinting is reqiored can be an empty string ""
//
// Returns:
//   - accessToken: A JWT token used for user authentication after successful login.
//   - refreshToken: A JWT token used for refreshing access tokens.
//   - err: An error, if any, that occurred during the login process.
func (s *Coreplainauth) login(ctx context.Context, identifier, password, fingerprint string) (accessToken, refreshToken string, err error) {
	s.logInfo("Login attempt for identifier: %s", identifier)

	if identifier == "" || password == "" {
		s.logWarn("Empty credentials provided")
		return "", "", errs.ErrEmptyCredentials
	}

	if len(password) > 254 {
		s.logWarn("Password too long for identifier: %s", identifier)
		return "", "", errs.ErrPasswordTooLong
	}

	if len(identifier) > 254 {
		s.logWarn("Identifier too long: %s", identifier)
		return "", "", errs.ErrIdentifierTooLong
	}

	var (
		userID       uuid.UUID
		passwordHash string
	)

	if re.MatchString(identifier) {
		s.logDebug("Identifier recognized as an email")
		userID, passwordHash, err = s.DB.GetUserPasswordAndIDByEmail(ctx, identifier)
	} else {
		s.logDebug("Identifier recognized as a username")
		userID, passwordHash, err = s.DB.GetUserPasswordAndIDByUsername(ctx, identifier)
	}

	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			s.logWarn("No user found with identifier: %s", identifier)
			return "", "", errs.ErrNoUserFound
		}
		s.logError("Database error while fetching user %s: %v", identifier, err)
		return "", "", err
	}

	s.logInfo("User found: %s", userID)

	isVerified, err := s.DB.GetIsverified(ctx, userID)
	if err != nil {
		s.logError("Error checking verification status for user %s: %v", userID, err)
		return "", "", err
	}

	if !isVerified {
		s.logWarn("User %s is not verified", userID)
		return "", "", errs.ErrNotVerified
	}

	if ok, _ := hashing.ComparePassword(password, passwordHash); !ok {
		s.logWarn("Incorrect password for user %s", userID)
		return "", "", errs.ErrIncorrectPassword
	}

	s.logInfo("Password verification successful for user %s", userID)

	accessToken, refreshToken, err = s.generateTokens(userID)
	if err != nil {
		return "", "", err
	}

	err = s.DB.SetRefreshToken(ctx, refreshToken, userID)
	if err != nil {
		s.logError("Error storing refresh token for user %s: %v", userID, err)
		return "", "", err
	}

	s.logInfo("Tokens successfully generated and stored for user %s", userID)

	if fingerprint != "" {
		s.logDebug("Checking fingerprint for user %s", userID)
		ff, err := s.DB.GetFingerprint(ctx, userID)
		if err != nil {
			s.logError("Error retrieving fingerprint for user %s: %v", userID, err)
			return "", "", err
		}

		if ff == "" {
			s.DB.SetFingerprint(ctx, userID, fingerprint)
		}

		if fingerprint != ff && s.WebhookConfig != nil {
			s.logWarn("New login detected from a different fingerprint for user %s", userID)
			go s.WebhookConfig.InvokeWebhook(context.Background(), identifier, "New Login detected")
		}
	}

	if s.WebhookConfig != nil {
		go s.WebhookConfig.InvokeWebhook(context.Background(), identifier, "Login successful")
	}

	s.logInfo("Login successful for user %s", userID)
	return accessToken, refreshToken, nil
}

// LoginHandler handles the login request by calling the login function and processing the result.
// It logs the login attempt and the success or failure of the login process.
//
// Parameters:
//   - ctx: The context used for database operations and actions.
//   - identifier: The username or email of the user attempting to log in.
//   - password: The password provided by the user to authenticate.
//   - fingerprint: A unique identifier for the user's device/browser, used for fingerprint checking.
//
// Returns:
//   - accessToken: A JWT token used for user authentication after successful login.
//   - refreshToken: A JWT token used for refreshing access tokens.
//   - err: An error, if any, that occurred during the login process.
func (s *Coreplainauth) LoginHandler(ctx context.Context, identifier, password, fingerprint string) (accessToken string, refreshToken string, err error) {
	s.logInfo("Handling login for identifier: %s", identifier)
	accessToken, refreshToken, err = s.login(ctx, identifier, password, fingerprint)
	if err != nil {
		s.logError("Login failed for %s: %v", identifier, err)
	} else {
		s.logInfo("User %s logged in successfully", identifier)
	}

	return accessToken, refreshToken, err
}
