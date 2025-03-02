package coreplainauth

import (
	"context"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

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

func (s *Coreplainauth) VerifiedUpdateEmailHandler(ctx context.Context, userID uuid.UUID, newEmail string) error {
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

	token, err := RandomString(32)
	if err != nil {
		return err
	}

	uname, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		return err
	}

	err = s.DB.SetUserVerificationDetails(ctx, userID, "update-email", newEmail, token, 1 * time.Hour)
	if err != nil {
		return err
	}

	return s.EmailProvider.SendEmail(oEmail, uname, s.Domain, token, "update-email")
}

func (s *Coreplainauth) VerifyUpdateEmailToken(ctx context.Context, token string) error {
	vt, vi, uid, exp, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		return err
	}

	if vt != "update-email" {
		return errs.ErrInvalidVerificationType
	}
	
	if time.Now().After(exp) {
		return errs.ErrInvalidToken
	}

	return s.DB.SetUserEmail(ctx, uid, vi)
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

func (s *Coreplainauth) VerifiedUpdateUsernameHandler(ctx context.Context, userID uuid.UUID, newUsername string) error {
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

	token, err := RandomString(32)
	if err != nil {
		return err
	}

	em, err := s.DB.GetUserEmail(ctx, userID)
	if err != nil {
		return errs.ErrNoChange
	}


	err = s.DB.SetUserVerificationDetails(ctx, userID, "update-username", newUsername, token, 1 * time.Hour)
	if err != nil {
		return err
	}

	return s.EmailProvider.SendEmail(em, un, s.Domain, token, "update-username")
}

func (s *Coreplainauth) VerifyUpdateUsernameToken(ctx context.Context, token string) error {
	vt, vi, uid, exp, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		return err
	}

	if vt != "update-username" {
		return errs.ErrInvalidVerificationType
	}
	
	if time.Now().After(exp) {
		return errs.ErrInvalidToken
	}

	return s.DB.SetUsername(ctx, uid, vi)
}

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

func (s *Coreplainauth) VerifiedUpdatePasswordHandler(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
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

	un, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		return errs.ErrNoChange
	}

	token, err := RandomString(32)
	if err != nil {
		return err
	}

	em, err := s.DB.GetUserEmail(ctx, userID)
	if err != nil {
		return errs.ErrNoChange
	}

	err = s.DB.SetUserVerificationDetails(ctx, userID, "update-password", newPasswordHash, token, 1 * time.Hour)
	if err != nil {
		return err
	}

	return s.EmailProvider.SendEmail(em, un, s.Domain, token, "update-password")
}

func (s *Coreplainauth) VerifyUpdatePasswordToken(ctx context.Context, token string) error {
	vt, vi, uid, exp, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		return err
	}

	if vt != "update-password" {
		return errs.ErrInvalidVerificationType
	}
	
	if time.Now().After(exp) {
		return errs.ErrInvalidToken
	}

	return s.DB.SetUserPassword(ctx, uid, vi)
}
