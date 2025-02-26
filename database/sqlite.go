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
	_, err := s.db.ExecContext(ctx, `INSERT INTO gauth_users (id, username, email, role, password_hash) VALUES (?, ?, ?, ?, ?)`, uid, username, email, role, passwordHash)
	if err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func (s *SqliteDB) GetUserPasswordAndIDByEmail(ctx context.Context, email string) (userID uuid.UUID, passwordHash string, err error) {
	var (
		uidStr       string
		passwordhash string
	)

	err = s.db.QueryRowContext(ctx, "SELECT password_hash, id FROM gauth_users WHERE email=?", email).Scan(&passwordhash, &uidStr)
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

	err = s.db.QueryRowContext(ctx, "SELECT password_hash, id FROM gauth_users WHERE username=?", username).Scan(&passwordhash, &uidStr)
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
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET refresh_token=? WHERE id=?", token, userid.String())
	return err
}

func (s *SqliteDB) GetRefreshToken(ctx context.Context, userid uuid.UUID) (string, error) {
	var token string
	err := s.db.QueryRowContext(ctx, "SELECT refresh_token FROM gauth_users WHERE id=?", userid.String()).Scan(&token)
	return token, err
}

func (s *SqliteDB) UpdateUserPassword(ctx context.Context, userid uuid.UUID, newPassword string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET password_hash=? WHERE id=?", newPassword, userid.String())
	return err
}

func (s *SqliteDB) DeleteUser(ctx context.Context, userid uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM gauth_users WHERE user_id=?", userid.String())
	return err
}

func (s *SqliteDB) EnableTwoFactor(ctx context.Context, userid uuid.UUID, secret string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET two_factor_enabled=true, two_factor_secret=? WHERE id=?", secret, userid.String())
	return err
}

func (s *SqliteDB) DisableTwoFactor(ctx context.Context, userid uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET two_factor_enabled=false, two_factor_secret=NULL WHERE id=?", userid.String())
	return err
}

func (s *SqliteDB) UpdateUserStatus(ctx context.Context, userid uuid.UUID, status string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET status=? WHERE id=?", status, userid.String())
	return err
}

func (s *SqliteDB) SetUserMetadata(ctx context.Context, userid uuid.UUID, metadata string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET metadata=? WHERE id=?", metadata, userid.String())
	return err
}

func (s *SqliteDB) GetUserMetadata(ctx context.Context, userid uuid.UUID) (string, error) {
	var metadata string
	err := s.db.QueryRowContext(ctx, "SELECT metadata FROM gauth_users WHERE id=?", userid.String()).Scan(&metadata)
	return metadata, err
}

func (s *SqliteDB) SetUserPreferences(ctx context.Context, userid uuid.UUID, preferences string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET preferences=? WHERE id=?", preferences, userid.String())
	return err
}

func (s *SqliteDB) GetUserPreferences(ctx context.Context, userid uuid.UUID) (string, error) {
	var preferences string
	err := s.db.QueryRowContext(ctx, "SELECT preferences FROM gauth_users WHERE id=?", userid.String()).Scan(&preferences)
	return preferences, err
}

func (s *SqliteDB) SetUserProfilePicture(ctx context.Context, userid uuid.UUID, profilePicture string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET profile_picture=? WHERE id=?", profilePicture, userid.String())
	return err
}

func (s *SqliteDB) GetUserProfilePicture(ctx context.Context, userid uuid.UUID) (string, error) {
	var profilePicture string
	err := s.db.QueryRowContext(ctx, "SELECT profile_picture FROM gauth_users WHERE id=?", userid.String()).Scan(&profilePicture)
	return profilePicture, err
}

func (s *SqliteDB) SetUserName(ctx context.Context, userid uuid.UUID, firstName, lastName string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET first_name=?, last_name=? WHERE id=?", firstName, lastName, userid.String())
	return err
}

func (s *SqliteDB) SetUserEmail(ctx context.Context, userid uuid.UUID, email string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET email=? WHERE id=?", email, userid.String())
	return err
}

func (s *SqliteDB) SetUserAddress(ctx context.Context, userid uuid.UUID, address string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET address=? WHERE id=?", address, userid.String())
	return err
}

func (s *SqliteDB) SetUserPhoneNumber(ctx context.Context, userid uuid.UUID, phoneNumber string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET phone_number=? WHERE id=?", phoneNumber, userid.String())
	return err
}

func (s *SqliteDB) SetUserRole(ctx context.Context, userid uuid.UUID, role string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET role=? WHERE id=?", role, userid.String())
	return err
}

func (s *SqliteDB) SetUserBirthDate(ctx context.Context, userid uuid.UUID, birthDate string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET birth_date=? WHERE id=?", birthDate, userid.String())
	return err
}

func (s *SqliteDB) SetUserStatus(ctx context.Context, userid uuid.UUID, status string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET status=? WHERE id=?", status, userid.String())
	return err
}

func (s *SqliteDB) SetTwoFactorSecret(ctx context.Context, userid uuid.UUID, secret string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE gauth_users SET two_factor_secret=? WHERE id=?", secret, userid.String())
	return err
}