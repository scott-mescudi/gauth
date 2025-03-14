package coreplainauth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/hashing"
)

func (s *Coreplainauth) VerifiedUpdatePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	s.logInfo("Attempting to update password for user ID: %s", userID)

	signupMethod, err := s.DB.GetSignupMethod(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve signup method for user %s: %v", userID, err)
		return err
	}

	if signupMethod != "plain" {
		s.logError("Invalid signup method for user %s: %s", userID, signupMethod)
		return errs.ErrInvalidSignupMethod
	}

	if oldPassword == "" || newPassword == "" {
		s.logError("Empty old or new password provided for user %s", userID)
		return errs.ErrEmptyCredentials
	}

	if oldPassword == newPassword {
		s.logInfo("Old password is the same as the new password for user %s", userID)
		return errs.ErrNoChange
	}

	if len(newPassword) > 254 {
		s.logError("New password is too long for user %s: %s", userID, newPassword)
		return errs.ErrPasswordTooLong
	}

	if len(oldPassword) > 254 {
		s.logError("Old password is too long for user %s: %s", userID, oldPassword)
		return errs.ErrPasswordTooLong
	}

	oldPasswordHash, err := s.DB.GetUserPasswordByID(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve old password hash for user %s: %v", userID, err)
		return err
	}

	if ok, _ := hashing.ComparePassword(oldPassword, oldPasswordHash); !ok {
		s.logError("Incorrect password for user %s", userID)
		return errs.ErrIncorrectPassword
	}

	newPasswordHash, err := hashing.HashPassword(newPassword)
	if err != nil {
		s.logError("Failed to hash new password for user %s: %v", userID, err)
		return err
	}

	if oldPasswordHash == newPasswordHash {
		s.logInfo("Old password is the same as the new password after hashing for user %s", userID)
		return errs.ErrNoChange
	}

	token := uuid.New()
	s.logInfo("Generated verification token for password update for user %s: %s", userID, token)

	err = s.DB.SetUserVerificationDetails(ctx, userID, "update-password", newPassword, token.String(), 15*time.Minute)
	if err != nil {
		s.logError("Failed to set user verification details for user %s: %v", userID, err)
		return err
	}

	email, err := s.DB.GetUserEmail(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve email for user %s: %v", userID, err)
		return err
	}

	username, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve username for user %s: %v", userID, err)
		return err
	}

	go func() {
		err = s.EmailProvider.SendEmail(email, username, fmt.Sprintf("%s/verify/%s?token=%s", s.Domain, "update-password", token), s.EmailTemplateConfig.UpdatePasswordTemplate)
		if err != nil {
			s.logError("Failed to send email to %s for user %s: %v", email, userID, err)
		}
	}()

	s.logInfo("Password update email successfully sent to %s for user %s", email, userID)
	return nil
}

func (s *Coreplainauth) VerifyUpdatePassword(ctx context.Context, token string) error {
	s.logInfo("Verifying password update for token: %s", token)

	if token == "" {
		s.logError("Empty token provided for password verification")
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

	if vt != "update-password" {
		s.logError("Invalid verification type for token %s: %s", token, vt)
		return errs.ErrInvalidVerificationType
	}

	s.logInfo("Successfully verified password update for user ID: %s", userID)
	s.LogoutHandler(ctx, userID)

	err = s.DB.SetUserPassword(ctx, userID, vi)
	if err != nil {
		s.logError("Failed to update password for user %s: %v", userID, err)
		return err
	}

	s.logInfo("Successfully updated password for user ID: %s", userID)
	return nil
}
