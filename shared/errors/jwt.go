package errors

import "errors"

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrInvalidUserID    = errors.New("invalid userID")
	ErrInvalidIssuer    = errors.New("invalid issuer")
	ErrInvalidTokenType = errors.New("invalid token type")
	ErrEmptyToken       = errors.New("token cannot be an empty string")
)
