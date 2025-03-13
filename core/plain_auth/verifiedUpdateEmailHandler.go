package coreplainauth

import (
	"context"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

func (s *Coreplainauth) VerifiedUpdateEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
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

	token := uuid.New()

	err = s.DB.SetUserVerificationDetails(ctx, userID, "update-email", newEmail, token.String(), 15*time.Minute)
	if err != nil {
		return err
	}

	uname, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		return err
	}

	err = s.EmailProvider.SendEmail(oemail, uname, s.Domain, token.String(), "update-email", s.EmailTemplateConfig.CancelUpdateEmailTemplate)
	if err != nil {
		return err
	}

	err = s.EmailProvider.SendEmail(newEmail, uname, s.Domain, token.String(), "update-email", s.EmailTemplateConfig.UpdateEmailTemplate)
	if err != nil {
		return err
	}

	return nil
}

func (s *Coreplainauth) VerifyUpdateEmail(ctx context.Context, token string) error {
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

	if vt != "update-email" {
		return errs.ErrInvalidVerificationType
	}

	return s.DB.SetUserEmail(ctx, userID, vi)
}

func (s *Coreplainauth) CancelVerifyUpdateEmail(ctx context.Context, token string) error {
	if token == "" {
		return errs.ErrEmptyToken
	}

	vt, _, userID, _, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		return err
	}

	if vt != "update-email" {
		return errs.ErrInvalidVerificationType
	}

	return s.DB.SetUserVerificationDetails(ctx, userID, "", "", "", 0)
}
