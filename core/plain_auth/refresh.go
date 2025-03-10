package coreplainauth

import (
	"context"
	"time"

	"github.com/scott-mescudi/gauth/shared/auth"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/variables"
)

func (s *Coreplainauth) RefreshHandler(ctx context.Context, token string) (accessToken, refreshToken string, err error) {
	if token == "" {
		return "", "", errs.ErrEmptyToken
	}

	uid, tokenType, err := auth.ValidateHmac(token)
	if err != nil {
		return "", "", err
	}

	if tokenType != variables.REFRESH_TOKEN {
		return "", "", errs.ErrInvalidTokenType
	}

	dbToken, err := s.DB.GetRefreshToken(ctx, uid)
	if err != nil {
		return "", "", err
	}

	if token != dbToken {
		return "", "", errs.ErrInvalidToken
	}

	accessToken, err = auth.GenerateHMac(uid, variables.ACCESS_TOKEN, time.Now().Add(s.AccessTokenExpiration))
	if err != nil {
		return "", "", err
	}

	refreshToken, err = auth.GenerateHMac(uid, variables.REFRESH_TOKEN, time.Now().Add(s.RefreshTokenExpiration))
	if err != nil {
		return "", "", err
	}

	err = s.DB.SetRefreshToken(ctx, refreshToken, uid)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil

}
