package coreplainauth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

// Core function for updating email
func (s *Coreplainauth) updateEmail(ctx context.Context, userID uuid.UUID, newEmail string, requireVerification bool) error {
	if newEmail == "" {
		return errs.ErrEmptyField
	}

	if len(newEmail) > 255 {
		return errs.ErrEmailTooLong
	}

	if !re.MatchString(newEmail) {
		return errs.ErrInvalidEmail
	}

	oEmail, err := s.DB.GetUserEmail(ctx, userID)
	if err != nil {
		return err
	}

	if oEmail == newEmail {
		return errs.ErrNoChange
	}

	if requireVerification {
		token, err := RandomString(32)
		if err != nil {
			return err
		}

		uname, err := s.DB.GetUsername(ctx, userID)
		if err != nil {
			return err
		}

		err = s.DB.SetUserVerificationDetails(ctx, userID, "update-email", newEmail, token, 1*time.Hour)
		if err != nil {
			return err
		}

		err = s.EmailProvider.SendEmail(oEmail, uname, s.Domain, token, "update-email")
		if err != nil {
			return err
		}
	} else {
		err = s.DB.SetUserEmail(ctx, userID, newEmail)
		if err != nil {
			return err
		}
	}


	if s.WebhookConfig != nil && err == nil {
		go s.WebhookConfig.InvokeWebhook(ctx, fmt.Sprintf("User %s updated email", userID), "update-email")
	}


	if s.LoggingOutput != nil {
		if err != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Email update failed for %s: %v\n", time.Now(), userID, err)
		} else {
			fmt.Fprintf(s.LoggingOutput, "%v [INFO] User %s updated email\n", time.Now(), userID)
		}
	}

	return err
}


func (s *Coreplainauth) UpdateEmailHandler(ctx context.Context, userID uuid.UUID, newEmail string) error {
	return s.updateEmail(ctx, userID, newEmail, false)
}


func (s *Coreplainauth) VerifiedUpdateEmailHandler(ctx context.Context, userID uuid.UUID, newEmail string) error {
	return s.updateEmail(ctx, userID, newEmail, true)
}


func (s *Coreplainauth) updateUsername(ctx context.Context, userID uuid.UUID, newUsername string, requireVerification bool) error {
	if newUsername == "" {
		return errs.ErrEmptyField
	}

	if len(newUsername) > 255 {
		return errs.ErrUsernameTooLong
	}

	if !validUsername(newUsername) {
		return errs.ErrInvalidUsername
	}

	un, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		return err
	}

	if un == newUsername {
		return errs.ErrNoChange
	}

	if requireVerification {
		token, err := RandomString(32)
		if err != nil {
			return err
		}

		em, err := s.DB.GetUserEmail(ctx, userID)
		if err != nil {
			return err
		}

		err = s.DB.SetUserVerificationDetails(ctx, userID, "update-username", newUsername, token, 1*time.Hour)
		if err != nil {
			return err
		}

		err = s.EmailProvider.SendEmail(em, un, s.Domain, token, "update-username")
		if err != nil {
			return err
		}
	} else {
		err = s.DB.SetUsername(ctx, userID, newUsername)
		if err != nil {
			return err
		}
	}

	
	if s.WebhookConfig != nil && err == nil {
		go s.WebhookConfig.InvokeWebhook(ctx, fmt.Sprintf("User %s updated username", userID), "update-username")
	}


	if s.LoggingOutput != nil {
		if err != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Username update failed for %s: %v\n", time.Now(), userID, err)
		} else {
			fmt.Fprintf(s.LoggingOutput, "%v [INFO] User %s updated username\n", time.Now(), userID)
		}
	}

	return err
}


func (s *Coreplainauth) UpdateUsernameHandler(ctx context.Context, userID uuid.UUID, newUsername string) error {
	return s.updateUsername(ctx, userID, newUsername, false)
}


func (s *Coreplainauth) VerifiedUpdateUsernameHandler(ctx context.Context, userID uuid.UUID, newUsername string) error {
	return s.updateUsername(ctx, userID, newUsername, true)
}


func (s *Coreplainauth) updatePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string, requireVerification bool) error {
	if newPassword == "" || oldPassword == "" {
		return errs.ErrEmptyField
	}

	passwordHash, err := s.DB.GetUserPasswordByID(ctx, userID)
	if err != nil {
		return err
	}

	if !ComparePassword(passwordHash, oldPassword) {
		return errs.ErrIncorrectPassword
	}

	if len(newPassword) > 72 {
		return errs.ErrPasswordTooLong
	}

	newPasswordHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	if requireVerification {
		token, err := RandomString(32)
		if err != nil {
			return err
		}

		em, err := s.DB.GetUserEmail(ctx, userID)
		if err != nil {
			return err
		}

		un, err := s.DB.GetUsername(ctx, userID)
		if err != nil {
			return err
		}

		err = s.DB.SetUserVerificationDetails(ctx, userID, "update-password", newPasswordHash, token, 1*time.Hour)
		if err != nil {
			return err
		}

		err = s.EmailProvider.SendEmail(em, un, s.Domain, token, "update-password")
		if err != nil {
			return err
		}
	} else {
		err = s.DB.SetUserPassword(ctx, userID, newPasswordHash)
		if err != nil {
			return err
		}
	}


	if s.WebhookConfig != nil && err == nil {
		go s.WebhookConfig.InvokeWebhook(ctx, fmt.Sprintf("User %s updated password", userID), "update-password")
	}


	if s.LoggingOutput != nil {
		if err != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Password update failed for %s: %v\n", time.Now(), userID, err)
		} else {
			fmt.Fprintf(s.LoggingOutput, "%v [INFO] User %s updated password\n", time.Now(), userID)
		}
	}

	return err
}


func (s *Coreplainauth) UpdatePasswordHandler(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	return s.updatePassword(ctx, userID, oldPassword, newPassword, false)
}

func (s *Coreplainauth) VerifiedUpdatePasswordHandler(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	return s.updatePassword(ctx, userID, oldPassword, newPassword, true)
}
