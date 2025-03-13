package coreplainauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/hashing"
)

func validUsername(username string) bool {
	return username != "" && !strings.ContainsRune(username, '@')
}

func (s *Coreplainauth) signup(ctx context.Context, fname, lname, username, email, password, role string, requireVerification bool) error {
	if !validUsername(username) {
		return errs.ErrInvalidUsername
	}

	if !re.MatchString(email) {
		return errs.ErrInvalidEmail
	}

	if password == "" || username == "" || email == "" || role == "" {
		return errs.ErrEmptyCredentials
	}

	if len(password) > 254 {
		return errs.ErrPasswordTooLong
	}

	if len(email) > 254 {
		return errs.ErrEmailTooLong
	}

	if len(username) > 254 {
		return errs.ErrUsernameTooLong
	}

	if role != "moderator" && role != "user" && role != "admin" && role != "guest" {
		return errs.ErrUnknownRole
	}

	hashedPassword, err := hashing.HashPassword(password)
	if err != nil {
		return errs.ErrFailedToHashPassword
	}

	isVerified := !requireVerification

	uid, err := s.DB.AddUser(ctx, fname, lname, username, email, role, hashedPassword, isVerified)
	if err != nil {
		return err
	}

	if requireVerification {
		token, err := RandomString(32)
		if err != nil {
			return err
		}

		err = s.DB.SetUserVerificationDetails(ctx, uid, "signup", "", token, 1*time.Hour)
		if err != nil {
			return err
		}

		if s.EmailProvider != nil {
			if err := s.EmailProvider.SendEmail(email, username, s.Domain, token, "signup", s.EmailTemplateConfig.SignupTemplate); err != nil {
				return err
			}
		} else {
			return errors.New("missing email provider config")
		}
	}

	return nil
}

// SignupHandler handles user sign-ups.
func (s *Coreplainauth) SignupHandler(ctx context.Context, fname, lname, username, email, password, role string, requireVerification bool) error {
	err := s.signup(ctx, fname, lname, username, email, password, role, requireVerification)

	if s.WebhookConfig != nil && err == nil {
		go func() {
			if webhookErr := s.WebhookConfig.InvokeWebhook(ctx, username, "User signed up"); webhookErr != nil {
				if s.Logger != nil {
					s.Logger.Error(fmt.Sprintf("Webhook failed for %s: %v", username, webhookErr))
				}
			}
		}()
	}

	if s.Logger != nil {
		if err != nil {
			s.Logger.Error(fmt.Sprintf("Signup attempt for %s: %v", username, err))
		} else {
			s.Logger.Info(fmt.Sprintf("Signup attempt for %s: %v", username, err))
		}
	}

	return err
}

// VerifySignupToken verifies the user's signup token.
func (s *Coreplainauth) VerifySignupToken(ctx context.Context, token string) error {
	vt, _, userID, expiry, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Error(fmt.Sprintf("Failed to retrieve verification details for token: %v", err))
		}
		return err
	}

	if vt != "signup" {
		if s.Logger != nil {
			s.Logger.Error(fmt.Sprintf("Invalid verification type for token: %s", token))
		}
		return errs.ErrInvalidVerificationType
	}

	if time.Now().After(expiry) {
		if s.Logger != nil {
			s.Logger.Error(fmt.Sprintf("Verification token expired: %s", token))
		}
		return errs.ErrInvalidToken
	}

	err = s.DB.SetIsverified(ctx, userID, true)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Error(fmt.Sprintf("Failed to set user as verified: %v", err))
		}
		return err
	}

	err = s.DB.SetUserVerificationDetails(ctx, userID, "", "", "", 0)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Error(fmt.Sprintf("Failed to clear verification details: %v", err))
		}
		return err
	}

	if s.Logger != nil {
		s.Logger.Info(fmt.Sprintf("Successfully verified user ID: %s", userID))
	}

	if s.WebhookConfig != nil {
		go func() {
			if webhookErr := s.WebhookConfig.InvokeWebhook(ctx, userID.String(), "User verified"); webhookErr != nil {
				if s.Logger != nil {
					s.Logger.Error(fmt.Sprintf("Webhook failed for user ID %s: %v", userID, webhookErr))
				}
			}
		}()
	}

	return nil
}
