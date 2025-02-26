package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
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

func (s *SqliteDB) AddUser(ctx context.Context, username, email, role, passwordHash string) (uuid.UUID, error) {
	var uid uuid.UUID = uuid.New()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO gauth_users (id, username, email, role) VALUES ($1, $2, $3, $4)`, uid, username, email, role)
	if err != nil {
		tx.Rollback()
		return uuid.Nil, err
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO gauth_user_auth (password_hash, user_id) VALUES ($1, $2)", passwordHash, uid)
	if err != nil {
		tx.Rollback()
		return uuid.Nil, err
	}

	if err := tx.Commit(); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func (s *SqliteDB) GetUserPasswordAndIDByEmail(ctx context.Context, email string) (userID uuid.UUID, passwordHash string, err error) {
	var (
		uidStr       string
		passwordhash string
	)

	err = s.db.QueryRowContext(ctx, "SELECT gua.password_hash, gu.id FROM gauth_users gu JOIN gauth_user_auth gua ON gu.id = gua.user_id WHERE gu.email=$1", email).Scan(&passwordhash, &uidStr)
	if err != nil {
		return uuid.Nil, "", err
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to get uuid")
	}

	return uid, passwordhash, nil
}

func (s *SqliteDB) GetUserPasswordAndIDByUsername(ctx context.Context, username string) (userID uuid.UUID, passwordHash string, err error) {
	var (
		uidStr       string
		passwordhash string
	)

	err = s.db.QueryRowContext(ctx, "SELECT gua.password_hash, gu.id FROM gauth_users gu JOIN gauth_user_auth gua ON gu.id = gua.user_id WHERE gu.username=$1", username).Scan(&passwordhash, &uidStr)
	if err != nil {
		return uuid.Nil, "", err
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("failed to get uuid")
	}

	return uid, passwordhash, nil
}

func (s *SqliteDB) SetRefreshToken(ctx context.Context, token string, userid uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_user_auth SET refresh_token=? WHERE user_id=?", token, userid.String())
	return err
}

func (s *SqliteDB) GetRefreshToken(ctx context.Context, userid uuid.UUID) (string, error) {
	var token string
	err := s.db.QueryRowContext(ctx, "SELECT refresh_token FROM gauth_user_auth WHERE user_id=?", userid.String()).Scan(&token)
	return token, err
}

func (s *SqliteDB) SetUserPassword(ctx context.Context, userid uuid.UUID, newPassword string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET password_hash=? WHERE id=?", newPassword, userid.String())
	return err
}

func (s *SqliteDB) DeleteUser(ctx context.Context, userid uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM gauth_users WHERE id=$1", userid.String())
	if err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (s *SqliteDB) SetUserFields(ctx context.Context, uuid uuid.UUID, fields *GauthUserFields) error {
	return nil
}
func (s *SqliteDB) GetUserFields(ctx context.Context, uuid uuid.UUID) (fields *GauthUserFields, err error) {
	return nil, nil
}
