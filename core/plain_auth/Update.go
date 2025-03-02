package coreplainauth

import (
	"context"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

func (s *Coreplainauth) UpdatePasswordHandler(userID uuid.UUID, oldPassword, newPassword string) error {
	passwordHash, err := s.DB.GetUserPasswordByID(context.Background(), userID)
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

	return s.DB.SetUserPassword(context.Background(), userID, newPasswordHash)
}

func (s *Coreplainauth) UpdateEmailHandler(userID uuid.UUID, oldEmail, newEmail string) error {
	if len(newEmail) > 255 {
		return errs.ErrEmailTooLong
	}

	if !re.MatchString(newEmail) {
		return errs.ErrInvalidEmail
	}

	oEmail, err := s.DB.GetUserEmail(context.Background(), userID)
	if err != nil {
		return err
	}

	if oldEmail != oEmail {
		return errs.ErrEmailMismatch
	}

	return s.DB.SetUserEmail(context.Background(), userID, newEmail)
}

func (s *Coreplainauth) UpdateUsernameHandler(userID uuid.UUID, newUsername string) error {
	if len(newUsername) > 255 {
		return errs.ErrUsernameTooLong
	}

	if !validUsername(newUsername) {
		return errs.ErrInvalidUsername
	}

	return s.DB.SetUsername(context.Background(), userID, newUsername)
}
