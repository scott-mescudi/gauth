package coreplainauth

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"time"
)

// DeleteAccount deletes a user account from the database.
// This function directly deletes a user’s account from the database identified by the `userID`.
// It does not involve any email verification or external processes.
func (s *Coreplainauth) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	return s.DB.DeleteUser(ctx, userID)
}

// VerifiedDeleteAccount initiates the process for deleting a user account with email verification.
// This function generates a verification token and stores it along with an expiration time in the database.
// The user will then receive two emails:
//  1. A verification email with a link to confirm the account deletion.
//  2. A cancellation email with a link to cancel the deletion.
//
// The user must click the corresponding link to confirm or cancel the deletion.
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
		// Send the verification email
		err = s.EmailProvider.SendEmail(email, username, fmt.Sprintf("%v/auth/user/verify/account-delete?token=%v", s.Domain, token), s.EmailTemplateConfig.DeleteAccountTemplate)
		if err != nil {
			s.logError("Failed to send verification email to %s: %v", email, err)
			return
		}

		// Send the cancellation email
		err = s.EmailProvider.SendEmail(email, username, fmt.Sprintf("%v/auth/user/verify/cancel-account-delete?token=%v", s.Domain, token), s.EmailTemplateConfig.CancelDeleteAccountTemplate)
		if err != nil {
			s.logError("Failed to send cancellation email to %s: %v", email, err)
			return
		}
	}()

	return nil
}

// VerifyDeleteAccount handles the verification process for account deletion based on the provided token.
// This function retrieves the verification details for the provided token from the database,
// checks if the token is valid and not expired, and then deletes the user account if the verification is successful.
// If the token is invalid, expired, or of the wrong type, an error is returned.
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

	err = s.DB.DeleteUser(ctx, userID)
	if err != nil {
		s.logError("Error deleting user account for user ID %s: %v", userID, err)
		return err
	}

	s.LogoutHandler(ctx, userID)
	s.logInfo("Successfully deleted account for user ID: %s", userID)
	return nil
}

// CancelDeleteAccount handles the cancellation of an account deletion process based on the provided token.
// The function retrieves the token's verification details from the database and clears the verification information,
// effectively canceling the account deletion process. If the token is invalid or expired, an error is returned.
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
