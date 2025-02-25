package database

import (
	"context"
	"time"
)

type DB interface {
	Ping(ctx context.Context) error
	Close()
}

type Config struct {
	MaxConns        int
	MinConns        int
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}
