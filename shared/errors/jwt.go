package errors

import "errors"


// errors for "/shared/auth"
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrInvalidUserID = errors.New("invalid userID")
	ErrInvalidIssuer = errors.New("invalid issuer")
	ErrInvalidTokenType = errors.New("invalid token type")
	ErrEmptyToken = errors.New("token cannot be a empty string")
)