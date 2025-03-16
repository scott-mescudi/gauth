package coreplainauth

import (
	"context"
	"github.com/google/uuid"
)

func (s *Coreplainauth) LogoutHandler(ctx context.Context, userID uuid.UUID) error {
	err := s.DB.SetRefreshToken(ctx, "", userID)
	if err != nil {
		s.logInfo("Failed toterminate session for userID %v", userID)
		return err
	}
	s.logInfo("Terminated session for userID %v", userID)
	return nil
}
