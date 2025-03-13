package coreplainauth

import (
	"context"
	"strings"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/hashing"
)

func (s *Coreplainauth) UpdateEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
	if newEmail == "" {
		return errs.ErrInvalidEmail

	}

	if len(newEmail) > 254 {
		return errs.ErrEmailTooLong
	}

	oemail, err := s.DB.GetUserEmail(ctx, userID)
	if err != nil {
		return err
	}

	if oemail == newEmail {
		return errs.ErrNoChange
	}

	if !re.MatchString(newEmail) {
		return errs.ErrInvalidEmail
	}

	return s.DB.SetUserEmail(ctx, userID, newEmail)
}

func (s *Coreplainauth) UpdateUsername(ctx context.Context, userID uuid.UUID, newUsername string) error {
	newUsername = strings.TrimSpace(newUsername)

	if newUsername == "" {
		return errs.ErrInvalidUsername
	}

	ousername, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		return err
	}

	if !validUsername(newUsername) {
		return errs.ErrInvalidUsername
	}

	if ousername == newUsername {
		return errs.ErrNoChange
	}

	if len(newUsername) > 254 {
		return errs.ErrUsernameTooLong
	}

	return s.DB.SetUsername(ctx, userID, newUsername)
}

func (s *Coreplainauth) UpdatePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	if oldPassword == "" || newPassword == "" {
		return errs.ErrEmptyCredentials
	}

	if oldPassword == newPassword {
		return errs.ErrNoChange
	}

	if len(newPassword) > 254 {
		return errs.ErrPasswordTooLong
	}

	if len(oldPassword) > 254 {
		return errs.ErrPasswordTooLong
	}

	if oldPassword == newPassword {
		return errs.ErrNoChange
	}

	oldPasswordHash, err := s.DB.GetUserPasswordByID(ctx, userID)
	if err != nil {
		return err
	}

	if ok, _ := hashing.ComparePassword(oldPassword, oldPasswordHash); !ok {
		return errs.ErrIncorrectPassword
	}

	newPasswordHash, err := hashing.HashPassword(newPassword)
	if err != nil {
		return err
	}

	if oldPasswordHash == newPasswordHash {
		return errs.ErrNoChange
	}

	return s.DB.SetUserPassword(ctx, userID, newPasswordHash)
}
