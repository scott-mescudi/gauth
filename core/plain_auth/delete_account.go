package coreplainauth

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"time"
)

func (s *Coreplainauth) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	return s.DB.DeleteUser(ctx, userID)
}

func (s *Coreplainauth) VerifiedDeleteAccount(ctx context.Context, userID uuid.UUID) error {
	email, err := s.DB.GetUserEmail(ctx, userID)
	if err != nil {
		return err
	}

	username, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		return err
	}

	token := uuid.New()
	err = s.DB.SetUserVerificationDetails(ctx, userID, "delete-account", "", token.String(), 1*time.Hour)
	if err != nil {
		return err
	}

	go func() {
		err = s.EmailProvider.SendEmail(email, username, fmt.Sprintf("%v/auth/user/verify/account-delete?token=%v", s.Domain, token), s.EmailTemplateConfig.DeleteAccountTemplate)
		if err != nil {
			return
		}

		err = s.EmailProvider.SendEmail(email, username, fmt.Sprintf("%v/auth/user/verify/cancel-account-delete?token=%v", s.Domain, token), s.EmailTemplateConfig.CancelDeleteAccountTemplate)
		if err != nil {
			return
		}
	}()

	return nil
}

func (s *Coreplainauth) VerifyDeleteAccount(ctx context.Context, token string) error {
	s.logInfo("Starting account deletion verification for token: %s", token)

	if token == "" {
		s.logError("Verification failed: token is empty")
		return errs.ErrEmptyToken
	}

	vt, _, userID, expiry, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		s.logError("Error retrieving verification details for token %s: %v", token, err)
		return err
	}

	if time.Now().After(expiry) {
		s.logError("Verification failed: token %s has expired", token)
		return errs.ErrInvalidToken
	}

	if vt != "delete-account" {
		s.logError("Verification failed: invalid verification type '%s' for token %s", vt, token)
		return errs.ErrInvalidVerificationType
	}

	s.logInfo("Account deletion verified for user ID: %s", userID)
	s.LogoutHandler(ctx, userID)

	err = s.DB.DeleteUser(ctx, userID)
	if err != nil {
		s.logError("Error deleting user account for user ID %s: %v", userID, err)
		return err
	}

	s.logInfo("Successfully deleted account for user ID: %s", userID)
	return nil
}

func (s *Coreplainauth) CancelDeleteAccount(ctx context.Context, token string) error {
	s.logInfo("Starting account deletion cancellation for token: %s", token)

	if token == "" {
		s.logError("Cancellation failed: token is empty")
		return errs.ErrEmptyToken
	}

	vt, _, userID, _, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		s.logError("Error retrieving verification details for token %s: %v", token, err)
		return err
	}

	if vt != "delete-account" {
		s.logError("Cancellation failed: invalid verification type '%s' for token %s", vt, token)
		return errs.ErrInvalidVerificationType
	}

	err = s.DB.SetUserVerificationDetails(ctx, userID, "", "", "", 0)
	if err != nil {
		s.logError("Error clearing verification details for user ID %s: %v", userID, err)
		return err
	}
	s.logInfo("Successfully cleared verification details for user ID: %s", userID)

	s.logInfo("Account deletion successfully canceled for user ID: %s", userID)
	return nil
}
