package errors

import "errors"

var (
	ErrEmptyCredentials  = errors.New("identifier or password cannot be empty")
	ErrIncorrectPassword = errors.New("incorrect user password")
	ErrInvalidUsername   = errors.New("username is invalid or empty")
	ErrInvalidEmail      = errors.New("invalid email format")
	ErrPasswordTooLong   = errors.New("password exceeds the maximum length of 254 characters")
	ErrUsernameTooLong   = errors.New("username exceeds the maximum length of 254 characters")
	ErrEmailTooLong      = errors.New("email exceeds the maximum length of 254 characters")
	ErrIdentifierTooLong = errors.New("identifier exceeds the maximum length of 254 characters")
	ErrEmailMismatch     = errors.New("emails dont match")
	ErrNotVerified       = errors.New("user is not verified")

	ErrUnknownRole          = errors.New("invalid role: must be one of 'admin', 'user', 'moderator', or 'guest'")
	ErrFailedToHashPassword = errors.New("failed to hash the password")
	ErrNoUserFound          = errors.New("no user with that identifier exists")
)
