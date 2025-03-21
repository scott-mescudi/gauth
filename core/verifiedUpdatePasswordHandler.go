package coreplainauth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
	"github.com/scott-mescudi/gauth/pkg/hashing"
	"github.com/scott-mescudi/gauth/pkg/variables"
)

// VerifiedUpdatePassword initiates the process to update the user's password.
// It performs the following tasks:
//  1. Verifies that the old password is correct.
//  2. Ensures the new password is different from the old password.
//  3. Hashes the new password and generates a verification token.
//  4. Sends a password update confirmation email to the user.
func (s *Coreplainauth) VerifiedUpdatePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	s.logInfo("Attempting to update password for user ID: %s", userID)

	signupMethod, err := s.DB.GetSignupMethod(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve signup method for user %s: %v", userID, err)
		return err
	}

	if signupMethod != "plain" {
		s.logError("Invalid signup method for user %s: %s", userID, signupMethod)
		return errs.ErrInvalidSignupMethod
	}

	if oldPassword == "" || newPassword == "" {
		s.logError("Empty old or new password provided for user %s", userID)
		return errs.ErrEmptyCredentials
	}

	if oldPassword == newPassword {
		s.logInfo("Old password is the same as the new password for user %s", userID)
		return errs.ErrNoChange
	}

	if len(newPassword) > 254 {
		s.logError("New password is too long for user %s: %s", userID, newPassword)
		return errs.ErrPasswordTooLong
	}

	if len(oldPassword) > 254 {
		s.logError("Old password is too long for user %s: %s", userID, oldPassword)
		return errs.ErrPasswordTooLong
	}

	oldPasswordHash, err := s.DB.GetUserPasswordByID(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve old password hash for user %s: %v", userID, err)
		return err
	}

	if ok, _ := hashing.ComparePassword(oldPassword, oldPasswordHash); !ok {
		s.logError("Incorrect password for user %s", userID)
		return errs.ErrIncorrectPassword
	}

	newPasswordHash, err := hashing.HashPassword(newPassword)
	if err != nil {
		s.logError("Failed to hash new password for user %s: %v", userID, err)
		return err
	}

	if oldPasswordHash == newPasswordHash {
		s.logInfo("Old password is the same as the new password after hashing for user %s", userID)
		return errs.ErrNoChange
	}

	token := uuid.New()
	s.logInfo("Generated verification token for password update for user %s: %s", userID, token)

	err = s.DB.SetUserVerificationDetails(ctx, userID, "update-password", newPassword, token.String(), 15*time.Minute)
	if err != nil {
		s.logError("Failed to set user verification details for user %s: %v", userID, err)
		return err
	}

	email, err := s.DB.GetUserEmail(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve email for user %s: %v", userID, err)
		return err
	}

	username, err := s.DB.GetUsername(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve username for user %s: %v", userID, err)
		return err
	}

	go func() {
		err = s.EmailProvider.SendEmail(email, username, fmt.Sprintf("%s/auth/verify/%s?token=%s", s.Domain, "password-update", token), s.EmailTemplateConfig.UpdatePasswordTemplate)
		if err != nil {
			s.logError("Failed to send email to %s for user %s: %v", email, userID, err)
		}
	}()

	s.logInfo("Password update email successfully sent to %s for user %s", email, userID)
	return nil
}

// VerifyUpdatePassword verifies the password update request using the provided token.
// It checks the validity of the token, confirms that it matches the "update-password" type,
// and ensures that the token has not expired. If valid, it updates the user's password in the database.
func (s *Coreplainauth) VerifyUpdatePassword(ctx context.Context, token string) error {
	s.logInfo("Verifying password update for token: %s", token)

	if token == "" {
		s.logError("Empty token provided for password verification")
		return errs.ErrEmptyToken
	}

	vt, vi, userID, expiry, err := s.DB.GetUserVerificationDetails(ctx, token)
	if err != nil {
		s.logError("Failed to retrieve verification details for token %s: %v", token, err)
		return err
	}

	if time.Now().After(expiry) {
		s.logError("Verification token expired for token %s", token)
		return errs.ErrInvalidToken
	}

	if vt != "update-password" {
		s.logError("Invalid verification type for token %s: %s", token, vt)
		return errs.ErrInvalidVerificationType
	}

	s.logInfo("Successfully verified password update for user ID: %s", userID)
	s.LogoutHandler(ctx, userID)

	err = s.DB.SetUserPassword(ctx, userID, vi)
	if err != nil {
		s.logError("Failed to update password for user %s: %v", userID, err)
		return err
	}

	s.logInfo("Successfully updated password for user ID: %s", userID)
	return nil
}

// HandleRecoverPassword initiates the password recovery process for a user by sending a password reset email.
// It verifies the user's email, generates a token, and sends a reset link with the token to the user's email.
func (s *Coreplainauth) HandleRecoverPassword(ctx context.Context, email string) error {
	s.logInfo("Starting password recovery process for email: %s", email)

	uid, err := s.DB.GetUserIDByEmail(ctx, email)
	if err != nil {
		s.logError("User ID lookup failed for email %s: %v", email, err)
		return err
	}
	s.logInfo("Retrieved user ID %s for email %s", uid, email)

	signupMethod, err := s.DB.GetSignupMethod(ctx, uid)
	if err != nil {
		s.logError("Failed to retrieve signup method for user %s: %v", uid, err)
		return err
	}
	s.logInfo("Signup method for user %s: %s", uid, signupMethod)

	if signupMethod != "plain" {
		s.logError("Password recovery not allowed for user %s due to signup method: %s", uid, signupMethod)
		return errs.ErrInvalidSignupMethod
	}

	tempToken, err := s.JWTConfig.GenerateHMac(uid, variables.ACCESS_TOKEN, time.Now().Add(15*time.Minute))
	if err != nil {
		s.logError("Failed to generate reset token for user %s: %v", uid, err)
		return err
	}
	s.logInfo("Generated password reset token for user %s", uid)
	username, err := s.DB.GetUsername(ctx, uid)
	if err != nil {
		s.logError("Failed to retrieve username for user %s: %v", uid, err)
		return err
	}
	s.logInfo("Retrieved username %s for user %s", username, uid)

	go func() {
		link := fmt.Sprintf("%s?token=%s", s.PasswordRecoverCallback, tempToken)
		emailErr := s.EmailProvider.SendEmail(email, username, link, s.EmailTemplateConfig.RecoverAccountTemplate)
		if emailErr != nil {
			s.logError("Email sending failed to %s for user %s: %v", email, uid, emailErr)
		} else {
			s.logInfo("Password reset email sent successfully to %s for user %s", email, uid)
		}
	}()

	return nil
}

// RecoverPassword processes the password reset request by validating the provided token.
// If the token is valid, it updates the user's password with the provided new password.
func (s *Coreplainauth) RecoverPassword(ctx context.Context, token, newPassword string) error {
	s.logInfo("Processing password reset request")

	if token == "" || newPassword == "" {
		s.logError("Password reset failed: empty token or password")
		return errs.ErrEmptyField
	}

	uid, tokenType, err := s.JWTConfig.ValidateHmac(token)
	if err != nil {
		s.logError("Invalid password reset token: %v", err)
		return errs.ErrInvalidToken
	}

	if tokenType != variables.ACCESS_TOKEN {
		s.logError("Invalid token type for user %v: expected %v, got %v", uid, variables.ACCESS_TOKEN, tokenType)
		return errs.ErrInvalidTokenType
	}

	hashedPassword, err := hashing.HashPassword(newPassword)
	if err != nil {
		s.logError("Failed to hash new password for user %s: %v", uid, err)
		return err
	}

	err = s.DB.SetUserPassword(ctx, uid, hashedPassword)
	if err != nil {
		s.logError("Failed to update password for user %s: %v", uid, err)
		return err
	}

	s.logInfo("Password updated successfully for user %s", uid)
	return nil
}
