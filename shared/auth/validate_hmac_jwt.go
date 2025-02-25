package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	v "github.com/scott-mescudi/gAuth/shared/variables"
	errs "github.com/scott-mescudi/gAuth/shared/errors"
)

func ValidateHmac(tokenString string) (userID int, tokenType int8, err error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.HMACSecretKey, nil
	})

	if err != nil {
		return -1, -1, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return -1, -1, errs.ErrInvalidToken
	}

	if claims.UserID <= 0 {
		return -1, -1, errs.ErrInvalidUserID
	}

	if claims.Issuer != v.Issuer {
		return -1, -1, errs.ErrInvalidIssuer
	}

	return claims.UserID, claims.TokenType, nil
}
