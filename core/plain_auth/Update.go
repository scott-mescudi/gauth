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

func (s *Coreplainauth) UpdateEmailHandler() {

}

func (s *Coreplainauth) UpdateUsernameHandler() {

}
