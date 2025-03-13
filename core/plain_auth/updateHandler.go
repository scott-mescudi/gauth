package coreplainauth

import (
	"context"
	"strings"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/hashing"
)

func (s *Coreplainauth) UpdateEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
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

	s.logInfo("Successfully updating email for user %s", userID)
	return s.DB.SetUserEmail(ctx, userID, newEmail)
}

func (s *Coreplainauth) UpdateUsername(ctx context.Context, userID uuid.UUID, newUsername string) error {
	s.logInfo("Attempting to update username for user ID: %s", userID)

	signupMethod, err := s.DB.GetSignupMethod(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve signup method for user %s: %v", userID, err)
		return err
	}

	if signupMethod != "plain" {
		s.logError("Invalid signup method for user %s: %s", userID, signupMethod)
		return errs.ErrInvalidSignupMethod
	}

	newUsername = strings.TrimSpace(newUsername)

	if newUsername == "" {
		s.logError("Empty new username provided for user %s", userID)
		return errs.ErrInvalidUsername
	}

	ousername, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve current username for user %s: %v", userID, err)
		return err
	}

	if !validUsername(newUsername) {
		s.logError("Invalid new username format for user %s: %s", userID, newUsername)
		return errs.ErrInvalidUsername
	}

	if ousername == newUsername {
		s.logInfo("No change in username for user %s, current username matches new username", userID)
		return errs.ErrNoChange
	}

	if len(newUsername) > 254 {
		s.logError("New username is too long for user %s: %s", userID, newUsername)
		return errs.ErrUsernameTooLong
	}

	s.logInfo("Successfully updating username for user %s", userID)
	return s.DB.SetUsername(ctx, userID, newUsername)
}

func (s *Coreplainauth) UpdatePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
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
		s.logError("Old or new password is empty for user %s", userID)
		return errs.ErrEmptyCredentials
	}

	if oldPassword == newPassword {
		s.logInfo("Old and new passwords are identical for user %s, no change", userID)
		return errs.ErrNoChange
	}

	if len(newPassword) > 254 {
		s.logError("New password is too long for user %s", userID)
		return errs.ErrPasswordTooLong
	}

	if len(oldPassword) > 254 {
		s.logError("Old password is too long for user %s", userID)
		return errs.ErrPasswordTooLong
	}

	oldPasswordHash, err := s.DB.GetUserPasswordByID(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve current password hash for user %s: %v", userID, err)
		return err
	}

	if ok, _ := hashing.ComparePassword(oldPassword, oldPasswordHash); !ok {
		s.logError("Incorrect old password for user %s", userID)
		return errs.ErrIncorrectPassword
	}

	newPasswordHash, err := hashing.HashPassword(newPassword)
	if err != nil {
		s.logError("Failed to hash new password for user %s: %v", userID, err)
		return err
	}

	if oldPasswordHash == newPasswordHash {
		s.logInfo("Old and new passwords are identical after hashing for user %s, no change", userID)
		return errs.ErrNoChange
	}

	s.logInfo("Successfully updating password for user %s", userID)
	return s.DB.SetUserPassword(ctx, userID, newPasswordHash)
}
