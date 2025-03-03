package coreplainauth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)


func (s *Coreplainauth) logAndWebhook(ctx context.Context, userID uuid.UUID, action string, err error) {
	if s.WebhookConfig != nil && err == nil {
		go s.WebhookConfig.InvokeWebhook(ctx, fmt.Sprintf("User %s performed %s", userID, action), action)
	}

	if s.LoggingOutput != nil {
		if err != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] %s failed for %s: %v\n", time.Now(), action, userID, err)
		} else {
			fmt.Fprintf(s.LoggingOutput, "%v [INFO] User %s successfully performed %s\n", time.Now(), userID, action)
		}
	}
}

func (s *Coreplainauth) verifyUpdate(ctx context.Context, token, action string) error {
	vt, vi, uid, exp, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		return err
	}
	if vt != action {
		return errs.ErrInvalidVerificationType
	}
	if time.Now().After(exp) {
		return errs.ErrInvalidToken
	}

	s.DB.SetUserVerificationDetails(ctx, uid, "", "", "", 0)

	switch action {
	case "update-email":
		err = s.DB.SetUserEmail(ctx, uid, vi)
	case "update-username":
		err = s.DB.SetUsername(ctx, uid, vi)
	case "update-password":
		err = s.DB.SetUserPassword(ctx, uid, vi)
	default:
		return errs.ErrInvalidVerificationType
	}

	s.logAndWebhook(ctx, uid, "verify-"+action, err)
	return err
}

func (s *Coreplainauth) VerifyUpdateEmailToken(ctx context.Context, token string) error {
	return s.verifyUpdate(ctx, token, "update-email")
}

func (s *Coreplainauth) VerifyUpdateUsernameToken(ctx context.Context, token string) error {
	return s.verifyUpdate(ctx, token, "update-username")
}

func (s *Coreplainauth) VerifyUpdatePasswordToken(ctx context.Context, token string) error {
	return s.verifyUpdate(ctx, token, "update-password")
}