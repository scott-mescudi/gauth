package coreplainauth

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/hashing"
	"github.com/scott-mescudi/gauth/shared/variables"
)

var (
	emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re         = regexp.MustCompile(emailRegex)
)

func (s *Coreplainauth) login(ctx context.Context, identifier, password, fingerprint string) (accessToken, refreshToken string, err error) {
	if identifier == "" || password == "" {
		return "", "", errs.ErrEmptyCredentials
	}

	if len(password) > 254 {
		return "", "", errs.ErrPasswordTooLong
	}

	if len(identifier) > 254 {
		return "", "", errs.ErrIdentifierTooLong
	}

	var (
		userID       uuid.UUID
		passwordHash string
	)

	if re.MatchString(identifier) {
		userID, passwordHash, err = s.DB.GetUserPasswordAndIDByEmail(ctx, identifier)
	} else {
		userID, passwordHash, err = s.DB.GetUserPasswordAndIDByUsername(ctx, identifier)
	}

	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return "", "", errs.ErrNoUserFound
		}
		return "", "", err
	}

	isVerified, err := s.DB.GetIsverified(ctx, userID)
	if err != nil {
		return "", "", err
	}

	if !isVerified {
		return "", "", errs.ErrNotVerified
	}

	if ok, _ := hashing.ComparePassword(password, passwordHash); !ok {
		return "", "", errs.ErrIncorrectPassword
	}

	accessToken, err = s.JWTConfig.GenerateHMac(userID, variables.ACCESS_TOKEN, time.Now().Add(s.AccessTokenExpiration))
	if err != nil {
		return "", "", err
	}

	refreshToken, err = s.JWTConfig.GenerateHMac(userID, variables.REFRESH_TOKEN, time.Now().Add(s.RefreshTokenExpiration))
	if err != nil {
		return "", "", err
	}

	err = s.DB.SetRefreshToken(ctx, refreshToken, userID)
	if err != nil {
		return "", "", err
	}

	if fingerprint != "" {
		ff, err := s.DB.GetFingerprint(ctx, userID)
		if err != nil {
			return "", "", err
		}

		if fingerprint != ff && s.WebhookConfig != nil {
			go s.WebhookConfig.InvokeWebhook(ctx, identifier, "New Login detected")
			if s.LoggingOutput != nil {
				fmt.Fprintf(s.LoggingOutput, "%v [WARN] New Login detected for %s: %v\n", time.Now(), identifier, fingerprint)
			}
		}
	}

	if s.WebhookConfig != nil {
		go s.WebhookConfig.InvokeWebhook(ctx, identifier, "Login successful")
	}

	return accessToken, refreshToken, nil
}

// The login handler contains the core logic for authentication.
// The identifier can be either an email or a password. The password must be provided in plaintext.
// The fingerprint refers to the device's fingerprint. If you don't want to include fingerprint logic,
// simply pass an empty string ("").
// The handler will return an access token and a refresh token on success,
// or an error if the authentication fails.
func (s *Coreplainauth) LoginHandler(ctx context.Context, identifier, password, fingerprint string) (accessToken string, refreshToken string, err error) {
	accessToken, refreshToken, err = s.login(ctx, identifier, password, fingerprint)
	if s.LoggingOutput != nil {
		if err != nil {
			fmt.Fprintf(s.LoggingOutput, "%v [ERROR] Login failed for %s: %v\n", time.Now(), identifier, err)
		} else {
			fmt.Fprintf(s.LoggingOutput, "%v [INFO] User %s logged in successfully\n", time.Now(), identifier)
		}
	}

	return accessToken, refreshToken, err
}
