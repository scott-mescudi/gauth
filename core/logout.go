package coreplainauth

import (
	"context"
	"github.com/google/uuid"
)

// LogoutHandler is responsible for handling user logouts by terminating their session.
// It clears the refresh token associated with the user to effectively log them out.
func (s *Coreplainauth) LogoutHandler(ctx context.Context, userID uuid.UUID) error {
	err := s.DB.SetRefreshToken(ctx, "", userID)
	if err != nil {
		s.logInfo("Failed toterminate session for userID %v", userID)
		return err
	}
	s.logInfo("Terminated session for userID %v", userID)
	return nil
}
