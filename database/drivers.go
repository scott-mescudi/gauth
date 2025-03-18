package database

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5/pgxpool"
	pg "github.com/scott-mescudi/gauth/database/postgres"
	se "github.com/scott-mescudi/gauth/database/sqlite"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

func NewPostgresDB(dsn string, config ...*Config) (*pg.PostgresDB, error) {
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}

	if len(config) == 1 && config[0] != nil {
		customConfig := config[0]
		if customConfig.MaxConns > 0 {
			poolConfig.MaxConns = int32(customConfig.MaxConns)
		}
		if customConfig.MinConns > 0 {
			poolConfig.MinConns = int32(customConfig.MinConns)
		}

		if customConfig.MaxConnLifetime > 0 {
			poolConfig.MaxConnLifetime = customConfig.MaxConnLifetime
		}
		if customConfig.MaxConnIdleTime > 0 {
			poolConfig.MaxConnIdleTime = customConfig.MaxConnIdleTime
		}
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, errs.ErrFailedToPingDatabase
	}

	return &pg.PostgresDB{Pool: pool}, nil
}

func NewSqliteDB(dsn string, config ...*Config) (*se.SqliteDB, error) {
	Pool, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	if len(config) == 1 && config[0] != nil {
		customConfig := config[0]
		if customConfig.MaxConns > 0 {
			Pool.SetMaxOpenConns(customConfig.MaxConns)
		}
		if customConfig.MaxConnLifetime > 0 {
			Pool.SetConnMaxLifetime(customConfig.MaxConnLifetime)
		}
		if customConfig.MaxConnIdleTime > 0 {
			Pool.SetConnMaxIdleTime(customConfig.MaxConnIdleTime)
		}
	}

	if err := Pool.Ping(); err != nil {
		return nil, errs.ErrFailedToPingDatabase
	}

	return &se.SqliteDB{Pool: Pool}, nil
}
