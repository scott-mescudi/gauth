package database

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	errs "github.com/scott-mescudi/gAuth/shared/errors"
)

type PostgresDB struct {
	pool *pgxpool.Pool
}

func NewPostgresDB(dsn string, config ...*Config) (*PostgresDB, error) {
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

	return &PostgresDB{pool: pool}, nil
}

func (s *PostgresDB) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *PostgresDB) Close() {
	s.pool.Close()
}
