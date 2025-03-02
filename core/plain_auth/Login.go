package coreplainauth

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/scott-mescudi/gauth/shared/auth"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/variables"
	"golang.org/x/crypto/bcrypt"
)

var (
	emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re         = regexp.MustCompile(emailRegex)
)

func (s *Coreplainauth) LoginHandler(ctx context.Context, identifier, password string) (accessToken, refreshToken string, err error) {
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
		if err != nil {
			if strings.Contains(err.Error(), "no rows") {
				return "", "", errs.ErrNoUserFound
			}

			return "", "", err
		}
	} else {
		userID, passwordHash, err = s.DB.GetUserPasswordAndIDByUsername(ctx, identifier)
		if err != nil {
			if strings.Contains(err.Error(), "no rows") {
				return "", "", errs.ErrNoUserFound
			}

			return "", "", err
		}
	}

	isverified, err := s.DB.GetIsverified(ctx, userID)
	if err != nil {
		return "", "", err
	}

	if !isverified {
		return "", "", errs.ErrNotVerified
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return "", "", errs.ErrIncorrectPassword
	}

	accessToken, err = auth.GenerateHMac(userID, variables.ACCESS_TOKEN, time.Now().Add(s.AccessTokenExpiration))
	if err != nil {
		return "", "", err
	}

	refreshToken, err = auth.GenerateHMac(userID, variables.REFRESH_TOKEN, time.Now().Add(s.RefreshTokenExpiration))
	if err != nil {
		return "", "", err
	}

	err = s.DB.SetRefreshToken(ctx, refreshToken, userID)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
