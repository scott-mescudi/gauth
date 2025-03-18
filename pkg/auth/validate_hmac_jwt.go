package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

func (s *JWTConfig) ValidateHmac(tokenString string) (UUID uuid.UUID, tokenType int8, err error) {
	if tokenString == "" {
		return uuid.Nil, -1, errs.ErrEmptyToken
	}

	if len(tokenString) < 20 {
		return uuid.Nil, -1, errs.ErrInvalidToken
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.Secret, nil
	})

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return uuid.Nil, -1, errs.ErrInvalidToken
	}

	if claims.UserID == uuid.Nil {
		return uuid.Nil, -1, errs.ErrInvalidUserID
	}

	if claims.Issuer != s.Issuer {
		return uuid.Nil, -1, errs.ErrInvalidIssuer
	}

	return claims.UserID, claims.TokenType, nil
}
