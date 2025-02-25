package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/shared/errors"
	v "github.com/scott-mescudi/gauth/shared/variables"
	"time"
)

type Claims struct {
	UserID    uuid.UUID
	TokenType int8
	jwt.RegisteredClaims
}

func GenerateHMac(userID uuid.UUID, tokenType int8, timeframe time.Time) (jwtToken string, err error) {
	if tokenType != 0 && tokenType != 1 {
		return "", errs.ErrInvalidTokenType
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UserID:    userID,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    v.Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(timeframe),
		},
	})

	tkstring, err := token.SignedString(v.HMACSecretKey)
	if err != nil {
		return "", err
	}

	return tkstring, nil
}
