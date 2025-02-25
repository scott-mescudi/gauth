package database

import (
	"context"
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

type SqliteDB struct {
	db *sql.DB
}

func NewSqliteDB(dsn string, config ...*Config) (*SqliteDB, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	if len(config) == 1 && config[0] != nil {
		customConfig := config[0]
		if customConfig.MaxConns > 0 {
			db.SetMaxOpenConns(customConfig.MaxConns)
		}
		if customConfig.MaxConnLifetime > 0 {
			db.SetConnMaxLifetime(customConfig.MaxConnLifetime)
		}
		if customConfig.MaxConnIdleTime > 0 {
			db.SetConnMaxIdleTime(customConfig.MaxConnIdleTime)
		}
	}

	if err := db.Ping(); err != nil {
		return nil, errs.ErrFailedToPingDatabase
	}

	return &SqliteDB{db: db}, nil
}

func (s *SqliteDB) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *SqliteDB) Close() {
	s.db.Close()
}
