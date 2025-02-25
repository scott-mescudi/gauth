package database

import (
	"context"
	"time"

	errs "github.com/scott-mescudi/gAuth/shared/errors"
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

func ConnectToDatabase(driver string, dsn string, config ...*Config) (database DB, err error) {
	switch driver {
	case "postgres":
		return NewPostgresDB(dsn, config...)
	case "sqlite":
		return NewSqliteDB(dsn, config...)
	}

	return nil, errs.ErrInvalidDriver
}
