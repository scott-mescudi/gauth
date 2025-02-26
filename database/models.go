package database

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type DB interface {
	Ping(ctx context.Context) error
	Close()
	AddUser(ctx context.Context, username, email, role, passwordHash string) (uuid.UUID, error)
	GetUserPasswordAndIDByEmail(ctx context.Context, email string) (userID uuid.UUID, passwordHash string, err error)
	GetUserPasswordAndIDByUsername(ctx context.Context, username string) (userID uuid.UUID, passwordHash string, err error)
	SetRefreshToken(ctx context.Context, token string, uuid uuid.UUID) error
	GetRefreshToken(ctx context.Context, userid uuid.UUID) (string, error)
}

type Config struct {
	MaxConns        int
	MinConns        int
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}
