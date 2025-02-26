package database

import (
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

func ConnectToDatabase(driver string, dsn string, config ...*Config) (database DB, err error) {
	switch driver {
	case "postgres":
		return NewPostgresDB(dsn, config...)
	case "sqlite":
		return NewSqliteDB(dsn, config...)
	}

	return nil, errs.ErrInvalidDriver
}
