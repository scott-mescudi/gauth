package coreplainauth

import (
	"context"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	"github.com/scott-mescudi/gauth/shared/variables"
)

// RefreshHandler processes a token refresh request. It validates the provided refresh token,
// checks it against the stored token in the database, and generates new access and refresh tokens.
// The generated tokens are then returned to the caller.
//
// Parameters:
//   - ctx (context.Context): The context to control the flow of the request.
//   - token (string): The refresh token provided by the user that needs to be validated and refreshed.
//
// Returns:
//   - accessToken (string): The newly generated access token for the user.
//   - refreshToken (string): The newly generated refresh token for the user.
//   - err (error): Any error encountered during the process (e.g., invalid token, database error).
//
// Errors:
//   - ErrEmptyToken: If the provided token is empty.
//   - ErrInvalidTokenType: If the token type is not a valid refresh token.
//   - ErrInvalidToken: If the provided token does not match the stored refresh token in the database.
//   - Other errors: If any issues arise during the validation, token generation, or database operations.
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

	accessToken, refreshToken, err = s.generateTokens(uid)
	if err != nil {
		return "", "", err
	}
	s.logDebug("Generated new tokens for user %s", uid)

	err = s.DB.SetRefreshToken(ctx, refreshToken, uid)
	if err != nil {
		s.logError("Failed to update refresh token for user %s in the database: %v", uid, err)
		return "", "", err
	}

	s.logInfo("Successfully refreshed tokens for user %s", uid)
	return accessToken, refreshToken, nil
}
