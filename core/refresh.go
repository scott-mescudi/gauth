package coreplainauth

import (
	"context"
	"time"

	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/variables"
)

func (s *Coreplainauth) RefreshHandler(ctx context.Context, token string) (accessToken, refreshToken string, err error) {
	s.logInfo("Processing token refresh request. Token: %s", token)

	if token == "" {
		s.logError("Empty token provided for refresh.")
		return "", "", errs.ErrEmptyToken
	}

	uid, tokenType, err := s.JWTConfig.ValidateHmac(token)
	if err != nil {
		s.logError("Failed to validate HMAC token: %v", err)
		return "", "", err
	}
	s.logDebug("Token validated successfully. User ID: %v, Token Type: %v", uid, tokenType)

	if tokenType != variables.REFRESH_TOKEN {
		s.logError("Invalid token type provided. Expected refresh token, but got: %v", tokenType)
		return "", "", errs.ErrInvalidTokenType
	}

	dbToken, err := s.DB.GetRefreshToken(ctx, uid)
	if err != nil {
		s.logError("Failed to retrieve refresh token for user %s from the database: %v", uid, err)
		return "", "", err
	}
	s.logDebug("Retrieved stored refresh token for user %s", uid)

	if token != dbToken {
		s.logError("Invalid refresh token provided for user %s", uid)
		return "", "", errs.ErrInvalidToken
	}

	s.logInfo("Generating new access and refresh tokens for user %s", uid)
	accessToken, err = s.JWTConfig.GenerateHMac(uid, variables.ACCESS_TOKEN, time.Now().Add(s.AccessTokenExpiration))
	if err != nil {
		s.logError("Failed to generate access token for user %s: %v", uid, err)
		return "", "", err
	}
	s.logDebug("Generated new access token for user %s", uid)

	refreshToken, err = s.JWTConfig.GenerateHMac(uid, variables.REFRESH_TOKEN, time.Now().Add(s.RefreshTokenExpiration))
	if err != nil {
		s.logError("Failed to generate refresh token for user %s: %v", uid, err)
		return "", "", err
	}
	s.logDebug("Generated new refresh token for user %s", uid)

	err = s.DB.SetRefreshToken(ctx, refreshToken, uid)
	if err != nil {
		s.logError("Failed to update refresh token for user %s in the database: %v", uid, err)
		return "", "", err
	}

	s.logInfo("Successfully refreshed tokens for user %s", uid)
	return accessToken, refreshToken, nil
}
