package coreplainauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	errs "github.com/scott-mescudi/gauth/shared/errors"
)

func validUsername(username string) bool {
	return username != "" && !strings.ContainsRune(username, '@')
}

func (s *Coreplainauth) signup(ctx context.Context, username, email, password, role string, requireVerification bool) error {
	if !validUsername(username) {
		return errs.ErrInvalidUsername
	}

	if !re.MatchString(email) {
		return errs.ErrInvalidEmail
	}

	if password == "" || username == "" || email == "" || role == "" {
		return errs.ErrEmptyCredentials
	}

	if len(password) > 72 {
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

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return errs.ErrFailedToHashPassword
	}

	isVerified := !requireVerification

	uid, err := s.DB.AddUser(ctx, username, email, role, hashedPassword, isVerified)
	if err != nil && !errors.Is(err, errs.ErrDuplicateKey) {
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
			if err := s.EmailProvider.SendEmail(email, username, s.Domain, token, "signup"); err != nil {
				return err
			}
		} else {
			return errors.New("missing email provider config")
		}
	}

	return nil
}

func (s *Coreplainauth) SignupHandler(ctx context.Context, username, email, password, role string, requireVerification bool) error {
	err := s.signup(ctx, username, email, password, role, requireVerification)

	
	if s.WebhookConfig != nil && err == nil {
		go func() {
			if webhookErr := s.WebhookConfig.InvokeWebhook(ctx, username, "User signed up"); webhookErr != nil {
				if s.LoggingOutput != nil {
					fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Webhook failed for %s: %v\n", time.Now(), username, webhookErr)
				}
			}
		}()
	}

	if s.LoggingOutput != nil {
		logLevel := "[INFO]"
		if err != nil {
			logLevel = "[ERROR]"
		}
		fmt.Fprintf(s.LoggingOutput, "%v %s Signup attempt for %s: %v\n", time.Now(), logLevel, username, err)
	}

	return err
}

func (s *Coreplainauth) VerifySignupToken(ctx context.Context, token string) error {
	vt, _, userID, expiry, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		if s.LoggingOutput != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Failed to retrieve verification details for token: %v\n", time.Now(), err)
		}
		return err
	}

	if vt != "signup" {
		if s.LoggingOutput != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Invalid verification type for token: %s\n", time.Now(), token)
		}
		return errs.ErrInvalidVerificationType
	}

	if time.Now().After(expiry) {
		if s.LoggingOutput != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Verification token expired: %s\n", time.Now(), token)
		}
		return errs.ErrInvalidToken
	}

	err = s.DB.SetIsverified(ctx, userID, true)
	if err != nil {
		if s.LoggingOutput != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Failed to set user as verified: %v\n", time.Now(), err)
		}
		return err
	}

	err = s.DB.SetUserVerificationDetails(ctx, userID, "", "", "", 0)
	if err != nil {
		if s.LoggingOutput != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Failed to clear verification details: %v\n", time.Now(), err)
		}
		return err
	}

	if s.LoggingOutput != nil {
		fmt.Fprintf(s.LoggingOutput, "%v [INFO] Successfully verified user ID: %s\n", time.Now(), userID)
	}


	if s.WebhookConfig != nil {
		go func() {
			if webhookErr := s.WebhookConfig.InvokeWebhook(ctx, userID.String(), "User verified"); webhookErr != nil {
				if s.LoggingOutput != nil {
					fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Webhook failed for user ID %s: %v\n", time.Now(), userID, webhookErr)
				}
			}
		}()
	}


	return nil
}


