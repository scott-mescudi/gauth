package errors

import "errors"

var (
	ErrEmptyCredentials        = errors.New("identifier or password cannot be empty")
	ErrIncorrectPassword       = errors.New("incorrect password. Please check your password and try again")
	ErrInvalidUsername         = errors.New("invalid or empty username. Please enter a valid username")
	ErrInvalidEmail            = errors.New("invalid email format. Please enter a valid email address")
	ErrPasswordTooLong         = errors.New("password is too long. It cannot exceed 254 characters")
	ErrUsernameTooLong         = errors.New("username is too long. It cannot exceed 254 characters")
	ErrEmailTooLong            = errors.New("email is too long. It cannot exceed 254 characters")
	ErrIdentifierTooLong       = errors.New("identifier is too long. It cannot exceed 254 characters")
	ErrEmailMismatch           = errors.New("the email addresses do not match. Please check and try again")
	ErrNotVerified             = errors.New("user account is not verified. Please verify your email address")
	ErrEmptyField              = errors.New("one or more required fields are empty. Please fill them in and try again")
	ErrNoChange                = errors.New("no changes detected. Please make sure you've made a modification before saving")
	ErrInvalidVerificationType = errors.New("invalid verification type. Please check the internal verification settings")
	ErrUnknownRole             = errors.New("invalid role provided. Role must be one of 'admin', 'user', 'moderator', or 'guest'")
	ErrFailedToHashPassword    = errors.New("unable to hash the password. Please try again")
	ErrNoUserFound             = errors.New("no user found with the given identifier. Please check your input and try again")
	ErrInvalidSignupMethod     = errors.New("unsupported signup method; only email and password are allowed")
)
