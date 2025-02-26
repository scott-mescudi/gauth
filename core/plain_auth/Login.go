package plainauth

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/scott-mescudi/gauth/shared/auth"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/variables"
)

var (
	emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re         = regexp.MustCompile(emailRegex)
)

func (s *PlainAuth) LoginHandler(identifier, password string) (accessToken, refreshToken string, err error) {
	if identifier == "" || password == "" {
		return "", "", errs.ErrEmptyCredentials
	}

	var (
		userID       uuid.UUID
		passwordHash string
	)

	if re.MatchString(identifier) {
		userID, passwordHash, err = s.DB.GetUserPasswordAndIDByEmail(context.Background(), identifier)
		if err != nil {
			if strings.Contains(err.Error(), "no rows") {
				return "", "", errs.ErrNoUserFound
			}

			return "", "", err
		}
	} else {
		userID, passwordHash, err = s.DB.GetUserPasswordAndIDByUsername(context.Background(), identifier)
		if err != nil {
			if strings.Contains(err.Error(), "no rows") {
				return "", "", errs.ErrNoUserFound
			}
			
			return "", "", err
		}
	}

	if !ComparePassword(passwordHash, password) {
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

	return accessToken, refreshToken, nil
}
