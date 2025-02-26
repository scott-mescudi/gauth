package plainauth

import (
	"context"
	"strings"
	"time"

	"github.com/scott-mescudi/gauth/shared/auth"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/variables"
)

func validUsername(username string) bool {
	if username == "" {
		return false
	}

	if strings.ContainsRune(username, '@') {
		return false
	}

	return true
}

func (s *PlainAuth) Signup(username, email, password, role string) (accessToken, refreshToken string, err error) {
	if !validUsername(username) {
		return "", "", errs.ErrInvalidUsername
	}

	if !re.MatchString(email) {
		return "", "", errs.ErrInvalidEmail
	}

	if len(password) > 254 {
		return "", "", errs.ErrPasswordTooLong
	}

	if role != "moderator" && role != "user" && role != "admin" && role != "guest" {
		return "", "", errs.ErrUnknownRole
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return "", "", errs.ErrFailedToHashPassword
	}

	userID, err := s.DB.AddUser(context.Background(), username, email, role, hashedPassword)
	if err != nil {
		return "", "", err
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
