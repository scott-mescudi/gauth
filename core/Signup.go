package coreplainauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
	"github.com/scott-mescudi/gauth/pkg/hashing"
)

// signup handles the user sign-up process, including input validation, password hashing,
// and storing the user in the database. If email verification is required, it generates
// a verification token and sends an email with the verification link.
//
// Parameters:
//   - ctx (context.Context): The context for controlling the flow of the sign-up request.
//   - fname (string): The user's first name. can be empty string if you dont want to store first name
//   - lname (string): The user's last name. can be empty string if you dont want to store last name
//   - username (string): The user's desired username. unique
//   - email (string): The user's email address. unique
//   - password (string): The user's password (will be hashed before saving).
//   - role (string): The user's role (e.g., "admin", "moderator", "user").
//   - requireVerification (bool): A flag indicating whether email verification is required.
//
// Returns:
//   - error: Returns an error if any issue occurs during sign-up (e.g., validation errors, database errors).
func (s *Coreplainauth) signup(ctx context.Context, fname, lname, username, email, password, role string, requireVerification bool) error {
	s.logDebug("Starting signup process for user: %s", username)

	if username == "" || strings.ContainsRune(username, '@') {
		s.logError("Invalid username provided: %s", username)
		return errs.ErrInvalidUsername
	}

	if !re.MatchString(email) {
		s.logError("Invalid email format provided: %s", email)
		return errs.ErrInvalidEmail
	}

	if password == "" || role == "" {
		s.logError("One or more required fields are empty: username=%s, email=%s, role=%s", username, email, role)
		return errs.ErrEmptyCredentials
	}

	if len(password) > 254 {
		s.logError("Password too long for username %s: %d characters", username, len(password))
		return errs.ErrPasswordTooLong
	}

	if len(email) > 254 {
		s.logError("Email too long for username %s: %d characters", username, len(email))
		return errs.ErrEmailTooLong
	}

	if len(username) > 254 {
		s.logError("Username too long: %s", username)
		return errs.ErrUsernameTooLong
	}

	if role != "moderator" && role != "user" && role != "admin" && role != "guest" {
		s.logError("Invalid role provided: %s for user %s", role, username)
		return errs.ErrUnknownRole
	}

	hashedPassword, err := hashing.HashPassword(password)
	if err != nil {
		s.logError("Failed to hash password for user %s: %v", username, err)
		return errs.ErrFailedToHashPassword
	}

	isVerified := !requireVerification

	s.logInfo("Attempting to add user %s to the database with role %s", username, role)
	uid, err := s.DB.AddUser(ctx, fname, lname, username, email, role, hashedPassword, isVerified)
	if err != nil {
		if requireVerification && errors.Is(err, errs.ErrDuplicateKey) {
			ouid, errCheck := s.DB.GetUserIDByEmail(ctx, email)
			if errCheck != nil {
				s.logError("Failed to add user %s to the database: %v", username, errs.ErrDuplicateKey)
				return errs.ErrDuplicateKey
			} else {
				isVerified, errCheck := s.DB.GetIsverified(ctx, ouid)
				if errCheck != nil {
					s.logError("Failed to check verification status for user %s: %v", username, errCheck)
					return errCheck
				}

				if !isVerified {
					s.logInfo("User %s already exists but is not verified", username)
				}
			}
		} else {
			s.logError("Failed to add user %s to the database: %v", username, err)
			return err
		}
	}

	if requireVerification {
		token := uuid.New()
		s.logInfo("User %s requires email verification, generating token: %s", username, token.String())

		err = s.DB.SetUserVerificationDetails(ctx, uid, "signup", "", token.String(), 1*time.Hour)
		if err != nil {
			s.logError("Failed to store verification token for user %s: %v", username, err)
			return err
		}

		if s.EmailProvider != nil {
			go func() {
				s.logInfo("Sending verification email to user %s at %s", username, email)
				err = s.EmailProvider.SendEmail(email, username, fmt.Sprintf("%s/auth/verify/%s?token=%s", s.Domain, "register", token), s.EmailTemplateConfig.SignupTemplate)
				if err != nil {
					s.logError("Failed to send verification email for user %s: %v", username, err)
				}
			}()
		} else {
			s.logError("Email provider is missing, cannot send verification email for user %s", username)
			return errors.New("missing email provider config")
		}
	}

	s.logInfo("Signup process completed for user: %s", username)
	return nil
}

// SignupHandler handles the user sign-up request and triggers any post-signup actions (e.g., webhook calls).
//
// Parameters:
//   - ctx (context.Context): The context for controlling the flow of the sign-up request.
//   - fname (string): The user's first name. can be empty string if you dont want to store first name
//   - lname (string): The user's last name. can be empty string if you dont want to store last name
//   - username (string): The user's desired username. unique
//   - email (string): The user's email address. unique
//   - password (string): The user's password (will be hashed before saving).
//   - role (string): The user's role (e.g., "admin", "moderator", "user").
//   - requireVerification (bool): A flag indicating whether email verification is required.
//
// Returns:
//   - error: Returns an error if any issue occurs during sign-up (e.g., validation errors, database errors).
func (s *Coreplainauth) SignupHandler(ctx context.Context, fname, lname, username, email, password, role string, requireVerification bool) error {
	s.logInfo("Processing signup request for username: %s", username)

	err := s.signup(ctx, fname, lname, username, email, password, role, requireVerification)

	if s.WebhookConfig != nil && err == nil {
		go func() {
			s.logInfo("Triggering webhook for user %s signup", username)
			if webhookErr := s.WebhookConfig.InvokeWebhook(context.Background(), username, "User signed up"); webhookErr != nil {
				s.logError("Webhook failed for %s: %v", username, webhookErr)
			} else {
				s.logInfo("Webhook successfully triggered for user %s signup", username)
			}
		}()
	}

	if err != nil {
		s.logError("Signup attempt for %s failed with error: %v", username, err)
	} else {
		s.logInfo("Signup attempt for %s succeeded", username)
	}

	return err
}

// VerifySignupToken verifies the user's signup token by checking its validity and expiration.
// If valid, the user is marked as verified.
//
// Parameters:
//   - ctx (context.Context): The context for controlling the flow of the verification request.
//   - token (string): The signup verification token to validate.
//
// Returns:
//   - error: Returns an error if any issue occurs during the verification process (e.g., invalid token, expired token).
func (s *Coreplainauth) VerifySignupToken(ctx context.Context, token string) error {
	s.logInfo("Verifying signup token: %s", token)

	vt, _, userID, expiry, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		s.logError("Failed to retrieve verification details for token %s: %v", token, err)
		return err
	}

	if vt != "signup" {
		s.logError("Invalid verification type for token %s: expected 'signup', got '%s'", token, vt)
		return errs.ErrInvalidVerificationType
	}

	if time.Now().After(expiry) {
		s.logError("Verification token expired: %s", token)
		return errs.ErrInvalidToken
	}

	err = s.DB.SetIsverified(ctx, userID, true)
	if err != nil {
		s.logError("Failed to mark user %s as verified: %v", userID, err)
		return err
	}

	err = s.DB.SetUserVerificationDetails(ctx, userID, "", "", "", 0)
	if err != nil {
		s.logError("Failed to clear verification details for user %s: %v", userID, err)
		return err
	}

	s.logInfo("Successfully verified user %s with ID %s", userID, userID)

	if s.WebhookConfig != nil {
		go func() {
			s.logInfo("Triggering webhook for user %s verification", userID)
			if webhookErr := s.WebhookConfig.InvokeWebhook(context.Background(), userID.String(), "User verified"); webhookErr != nil {
				s.logError("Webhook failed for user ID %s verification: %v", userID, webhookErr)
			} else {
				s.logInfo("Webhook successfully triggered for user %s verification", userID)
			}
		}()
	}

	return nil
}
