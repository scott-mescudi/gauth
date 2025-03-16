package coreplainauth

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/scott-mescudi/gauth/shared/compression"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

const maxBase64Size = 2 * 1024 * 1024

var re2 = regexp.MustCompile(`^[a-zA-Z0-9+/=]*$`)

func (s *Coreplainauth) UploadImage(ctx context.Context, userID uuid.UUID, base64String string) error {
	s.logInfo("Attempting to upload image for user ID: %s", userID)

	parts := strings.SplitN(base64String, ",", 2)
	if len(parts) < 2 {
		s.logError("Invalid base64 string format for user %s", userID)
		return errs.ErrInvalidBase64String
	}
	base64String = parts[1]

	if len(base64String) > int(maxBase64Size) {
		s.logError("Base64 string too large for user %s: %d bytes", userID, len(base64String))
		return errs.ErrImageToLarge
	}

	if !re2.MatchString(base64String) {
		s.logError("Invalid characters in base64 string for user %s", userID)
		return errs.ErrInvalidBase64String
	}

	compressed, err := compression.CompressZSTD([]byte(base64String))
	if err != nil {
		s.logError("Compression failed for image upload for user %s: %v", userID, err)
		return err
	}

	err = s.DB.SetUserImage(ctx, userID, compressed)
	if err != nil {
		s.logError("Failed to save compressed image for user %s: %v", userID, err)
		return err
	}

	s.logInfo("Image successfully uploaded and saved for user %s", userID)
	return nil
}

func (s *Coreplainauth) GetImage(ctx context.Context, userID uuid.UUID) (string, error) {
	s.logInfo("Attempting to retrieve image for user ID: %s", userID)

	img, err := s.DB.GetUserImage(ctx, userID)
	if err != nil {
		s.logError("Failed to retrieve image for user %s: %v", userID, err)
		return "", err
	}

	if len(img) == 0 {
		return "", errs.ErrNoImageFound
	}

	decompressed, err := compression.DecompressZSTD(img)
	if err != nil {
		s.logError("Failed to decompress image for user %s: %v", userID, err)
		return "", err
	}

	s.logInfo("Image successfully retrieved and decompressed for user %s", userID)
	return string(decompressed), nil
}

func (s *Coreplainauth) GetUserDetails(ctx context.Context, userID uuid.UUID, info *UserSessionDetails) (err error) {
	info.ID = userID

	username, email, firstName, lastName, signupMethod, role, created, last_login, err := s.DB.GetUserDetails(ctx, userID)
	if err != nil {
		return err
	}

	info.Username = username
	info.Email = email
	info.FirstName = firstName
	info.LastName = lastName
	info.SignupMethod = signupMethod
	info.Role = role
	info.Created = created
	info.LastLogin = last_login.Time

	img, err := s.GetImage(ctx, userID)
	if err != nil {
		if img == "" {
			info.ProfilePicture = ""
		} else {
			return err
		}
	} else {
		info.ProfilePicture = img
	}

	return nil
}
