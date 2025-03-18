package coreplainauth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

// VerifiedUpdateEmail initiates the process to update the user's email address. This includes:
//  1. Validating the user's current signup method.
//  2. Checking if the new email is valid and not the same as the current email.
//  3. Generating a verification token for the email update.
//  4. Sending two emails to the user: one for canceling the update and one for confirming the update.
func (s *Coreplainauth) VerifiedUpdateEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
	s.logInfo("Attempting to update email for user ID: %s", userID)

	signupMethod, err := s.DB.GetSignupMethod(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve signup method for user %s: %v", userID, err)
		return err
	}

	if signupMethod != "plain" {
		s.logError("Invalid signup method for user %s: %s", userID, signupMethod)
		return errs.ErrInvalidSignupMethod
	}

	if newEmail == "" {
		s.logError("Empty new email provided for user %s", userID)
		return errs.ErrInvalidEmail
	}

	if len(newEmail) > 254 {
		s.logError("New email is too long for user %s: %s", userID, newEmail)
		return errs.ErrEmailTooLong
	}

	oemail, err := s.DB.GetUserEmail(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve current email for user %s: %v", userID, err)
		return err
	}

	if oemail == newEmail {
		s.logInfo("No change in email for user %s, current email matches new email", userID)
		return errs.ErrNoChange
	}

	if !re.MatchString(newEmail) {
		s.logError("Invalid new email format for user %s: %s", userID, newEmail)
		return errs.ErrInvalidEmail
	}

	token := uuid.New()
	s.logInfo("Generated verification token for user %s: %s", userID, token)

	err = s.DB.SetUserVerificationDetails(ctx, userID, "update-email", newEmail, token.String(), 15*time.Minute)
	if err != nil {
		s.logError("Failed to set user verification details for user %s: %v", userID, err)
		return err
	}

	uname, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve username for user %s: %v", userID, err)
		return err
	}

	go func() {
		// Send cancellation email
		err = s.EmailProvider.SendEmail(oemail, uname, fmt.Sprintf("%s/auth/verify/%s?token=%s", s.Domain, "cancel-email-update", token), s.EmailTemplateConfig.CancelUpdateEmailTemplate)
		if err != nil {
			s.logError("Failed to send cancellation email to %s: %v", oemail, err)
		}

		// Send confirmation email
		err = s.EmailProvider.SendEmail(newEmail, uname, fmt.Sprintf("%s/auth/verify/%s?token=%s", s.Domain, "email-update", token), s.EmailTemplateConfig.UpdateEmailTemplate)
		if err != nil {
			s.logError("Failed to send confirmation email to %s: %v", newEmail, err)
		}
	}()

	s.logInfo("Successfully initiated email update for user %s", userID)
	return nil
}

// VerifyUpdateEmail verifies the email update request using the token. It checks the validity of the token,
// confirms that it matches the "update-email" type, and ensures that the token has not expired. If valid,
// it updates the user's email in the database and logs them out for security purposes.
func (s *Coreplainauth) VerifyUpdateEmail(ctx context.Context, token string) error {
	s.logInfo("Verifying email update for token: %s", token)

	if token == "" {
		s.logError("Empty token provided for email verification")
		return errs.ErrEmptyToken
	}

	vt, vi, userID, expiry, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		s.logError("Failed to retrieve verification details for token %s: %v", token, err)
		return err
	}

	if time.Now().After(expiry) {
		s.logError("Verification token expired for token %s", token)
		return errs.ErrInvalidToken
	}

	if vt != "update-email" {
		s.logError("Invalid verification type for token %s: %s", token, vt)
		return errs.ErrInvalidVerificationType
	}

	s.logInfo("Successfully verified email update for user ID: %s", userID)
	s.LogoutHandler(ctx, userID)

	err = s.DB.SetUserEmail(ctx, userID, vi)
	if err != nil {
		s.logError("Failed to update email for user %s: %v", userID, err)
		return err
	}

	s.logInfo("Successfully updated email for user ID: %s", userID)
	return nil
}

// CancelVerifyUpdateEmail cancels the email update process by invalidating the verification token.
// It ensures that the provided token is valid and corresponds to an email update request.
// If successful, the verification details are cleared from the database.
func (s *Coreplainauth) CancelVerifyUpdateEmail(ctx context.Context, token string) error {
	s.logInfo("Canceling email update for token: %s", token)

	if token == "" {
		s.logError("Empty token provided for canceling email update")
		return errs.ErrEmptyToken
	}

	vt, _, userID, _, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		s.logError("Failed to retrieve verification details for token %s: %v", token, err)
		return err
	}

	if vt != "update-email" {
		s.logError("Invalid verification type for token %s: %s", token, vt)
		return errs.ErrInvalidVerificationType
	}

	s.logInfo("Successfully canceled email update for user ID: %s", userID)
	s.LogoutHandler(ctx, userID)

	err = s.DB.SetUserVerificationDetails(ctx, userID, "", "", "", 0)
	if err != nil {
		s.logError("Failed to clear verification details for user %s: %v", userID, err)
		return err
	}

	s.logInfo("Successfully cleared verification details for user ID: %s", userID)
	return nil
}
