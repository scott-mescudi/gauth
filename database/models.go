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
}

type Config struct {
	MaxConns        int
	MinConns        int
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}
