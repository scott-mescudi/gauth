package coreplainauth

import (
	"context"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/hashing"
)

func (s *Coreplainauth) VerifiedUpdatePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	signupMethod, err := s.DB.GetSignupMethod(ctx, userID)
	if err != nil {
		return err
	}

	if signupMethod != "plain" {
		return errs.ErrInvalidSignupMethod
	}

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

	token := uuid.New()

	err = s.DB.SetUserVerificationDetails(ctx, userID, "update-password", newPassword, token.String(), 15*time.Minute)
	if err != nil {
		return err
	}

	email, err := s.DB.GetUserEmail(ctx, userID)
	if err != nil {
		return err
	}

	username, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		return err
	}

	return s.EmailProvider.SendEmail(email, username, s.Domain, token.String(), "update-password", s.EmailTemplateConfig.UpdatePasswordTemplate)
}

func (s *Coreplainauth) VerifyUpdatePassword(ctx context.Context, token string) error {
	if token == "" {
		return errs.ErrEmptyToken
	}

	vt, vi, userID, expiry, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		return err
	}

	if time.Now().After(expiry) {
		return errs.ErrInvalidToken
	}

	if vt != "update-password" {
		return errs.ErrInvalidVerificationType
	}

	s.LogoutHandler(ctx, userID)

	return s.DB.SetUserPassword(ctx, userID, vi)
}
