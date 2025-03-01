package coreplainauth

import (
	"context"
	"strings"

	errs "github.com/scott-mescudi/gauth/shared/errors"
)

func validUsername(username string) bool {
	if username == "" {
		return false
	}

	if strings.ContainsRune(username, '@') {
		return false
	}

	return true
}

func (s *Coreplainauth) SignupHandler(username, email, password, role string) (err error) {
	if !validUsername(username) {
		return errs.ErrInvalidUsername
	}

	if !re.MatchString(email) {
		return errs.ErrInvalidEmail
	}

	if password == "" || username == "" || email == "" || role == "" {
		return errs.ErrEmptyCredentials
	}

	if len(password) > 72 {
		return errs.ErrPasswordTooLong
	}

	if len(email) > 254 {
		return errs.ErrEmailTooLong
	}

	if len(username) > 254 {
		return errs.ErrUsernameTooLong
	}

	if role != "moderator" && role != "user" && role != "admin" && role != "guest" {
		return errs.ErrUnknownRole
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		return errs.ErrFailedToHashPassword
	}

	ctx := context.Background()

	_, err = s.DB.AddUser(ctx, username, email, role, hashedPassword, true)
	if err != nil {
		return err
	}

	return nil
}

// func (s *Coreplainauth) SignupHandlerWithEmailVerification(username, email, password, role string) (err error)
