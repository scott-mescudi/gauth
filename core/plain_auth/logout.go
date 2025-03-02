package coreplainauth

import (
	"context"

	"github.com/google/uuid"
)

func (s *Coreplainauth) LogoutHandler(ctx context.Context, userID uuid.UUID) error {
	return s.DB.SetRefreshToken(ctx, "", userID)
}