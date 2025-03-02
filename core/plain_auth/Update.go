package coreplainauth

import (
	"context"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

func (s *Coreplainauth) UpdatePasswordHandler(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
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

	return s.DB.SetUserPassword(ctx, userID, newPasswordHash)
}

func (s *Coreplainauth) UpdateEmailHandler(ctx context.Context, userID uuid.UUID, newEmail string) error {
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

	return s.DB.SetUserEmail(ctx, userID, newEmail)
}

func (s *Coreplainauth) UpdateUsernameHandler(ctx context.Context, userID uuid.UUID, newUsername string) error {
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
		return errs.ErrNoChange
	}

	if un == newUsername {
		return nil
	}

	return s.DB.SetUsername(ctx, userID, newUsername)
}
