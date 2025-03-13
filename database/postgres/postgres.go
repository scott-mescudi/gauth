package database

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	errs "github.com/scott-mescudi/gauth/shared/errors"
)

var postgresSchema = `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS gauth_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    first_name VARCHAR(255),
    signup_method VARCHAR(255) DEFAULT 'plain' CHECK (signup_method IN ('github', 'google', 'microsoft', 'discord', 'plain')),
    last_name VARCHAR(255),
    profile_picture BYTEA DEFAULT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'user', 'moderator', 'guest')),
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gauth_user_verification (
    user_id UUID PRIMARY KEY REFERENCES gauth_user(id) ON DELETE CASCADE,
    verificaton_item TEXT,
    verification_type VARCHAR(50) DEFAULT 'none',
    verification_token TEXT,
    token_expiry TIMESTAMP,
    isverified BOOLEAN
);


CREATE TABLE IF NOT EXISTS gauth_user_auth (
    user_id UUID PRIMARY KEY REFERENCES gauth_user(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    last_login TIMESTAMP,
    last_password_change TIMESTAMP,
    last_email_change TIMESTAMP,
    last_username_change TIMESTAMP,
    auth_provider VARCHAR(50),
    login_fingerprint TEXT,
    auth_id VARCHAR(255),
    refresh_token TEXT DEFAULT NULL
);
`

type PostgresDB struct {
	Pool *pgxpool.Pool
}

func (s *PostgresDB) Migrate() {
	s.Pool.Exec(context.Background(), postgresSchema)
}

func (s *PostgresDB) Ping(ctx context.Context) error {
	return s.Pool.Ping(ctx)
}

func (s *PostgresDB) Close() {
	s.Pool.Close()
}

func (s *PostgresDB) AddUser(ctx context.Context, fname, lname, username, email, role, passwordHash string, isVerified bool) (uuid.UUID, error) {
	var uid uuid.UUID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	err = tx.QueryRow(ctx, `INSERT INTO gauth_user (username, email, role, first_name, last_name) VALUES ($1, $2, $3, $4, $5) RETURNING id`, username, strings.ToLower(email), role, fname, lname).Scan(&uid)
	if err != nil {
		tx.Rollback(ctx)
		if strings.Contains(err.Error(), "23505") {
			return uuid.Nil, errs.ErrDuplicateKey
		}
		return uuid.Nil, err
	}

	_, err = tx.Exec(ctx, "INSERT INTO gauth_user_auth (password_hash, user_id) VALUES ($1, $2)", passwordHash, uid)
	if err != nil {
		tx.Rollback(ctx)
		return uuid.Nil, err
	}

	_, err = tx.Exec(ctx, "INSERT INTO gauth_user_verification (user_id, isverified) VALUES ($1, $2)", uid, isVerified)
	if err != nil {
		tx.Rollback(ctx)
		return uuid.Nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func (s *PostgresDB) GetUserPasswordAndIDByEmail(ctx context.Context, email string) (userID uuid.UUID, passwordHash string, err error) {
	var (
		uid          uuid.UUID
		passwordhash string
	)
	err = s.Pool.QueryRow(ctx, "SELECT gua.password_hash, gu.id FROM gauth_user gu JOIN gauth_user_auth gua ON gu.id = gua.user_id WHERE gu.email=$1", strings.ToLower(email)).Scan(&passwordhash, &uid)
	if err != nil {
		return uuid.Nil, "", err
	}

	return uid, passwordhash, nil
}

func (s *PostgresDB) GetUserPasswordAndIDByUsername(ctx context.Context, username string) (userID uuid.UUID, passwordHash string, err error) {
	var (
		uid          uuid.UUID
		passwordhash string
	)
	err = s.Pool.QueryRow(ctx, "SELECT gua.password_hash, gu.id FROM gauth_user gu JOIN gauth_user_auth gua ON gu.id = gua.user_id WHERE gu.username=$1", username).Scan(&passwordhash, &uid)
	if err != nil {
		return uuid.Nil, "", err
	}

	return uid, passwordhash, nil
}

func (s *PostgresDB) SetRefreshToken(ctx context.Context, token string, userid uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, "UPDATE gauth_user_auth SET refresh_token=$1 WHERE user_id=$2", token, userid)
	return err
}

func (s *PostgresDB) GetRefreshToken(ctx context.Context, userid uuid.UUID) (string, error) {
	var token string
	err := s.Pool.QueryRow(ctx, "SELECT refresh_token FROM gauth_user_auth WHERE user_id=$1", userid).Scan(&token)
	return token, err
}

func (s *PostgresDB) SetUserPassword(ctx context.Context, userid uuid.UUID, newPassword string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE gauth_user_auth SET password_hash=$1 WHERE user_id=$2", newPassword, userid)
	if err != nil {
		tx.Rollback(ctx)
		return err
	}

	_, err = tx.Exec(ctx, "UPDATE gauth_user_auth SET last_password_change=$1 WHERE user_id=$2", time.Now(), userid)
	if err != nil {
		tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

func (s *PostgresDB) DeleteUser(ctx context.Context, userid uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, "DELETE FROM gauth_user WHERE id=$1", userid)
	if err != nil {
		tx.Rollback(ctx)
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	return nil
}

func (s *PostgresDB) GetUserPasswordByID(ctx context.Context, userid uuid.UUID) (string, error) {
	var passwordHash string
	err := s.Pool.QueryRow(context.Background(), "SELECT password_hash from gauth_user_auth WHERE user_id=$1", userid).Scan(&passwordHash)
	return passwordHash, err
}

func (s *PostgresDB) SetUserEmail(ctx context.Context, userid uuid.UUID, newEmail string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, "UPDATE gauth_user SET email=$1 WHERE id=$2", strings.ToLower(newEmail), userid)
	if err != nil {
		tx.Rollback(ctx)
		if strings.Contains(err.Error(), "23505") {
			return errs.ErrDuplicateKey
		}

		return err
	}

	_, err = tx.Exec(ctx, "UPDATE gauth_user_auth SET last_email_change=$1 WHERE user_id=$2", time.Now(), userid)
	if err != nil {
		tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

func (s *PostgresDB) GetUserEmail(ctx context.Context, userid uuid.UUID) (string, error) {
	var op string
	err := s.Pool.QueryRow(ctx, "SELECT email FROM gauth_user WHERE id=$1", userid).Scan(&op)
	return op, err
}

func (s *PostgresDB) SetIsverified(ctx context.Context, userid uuid.UUID, isVerified bool) error {
	_, err := s.Pool.Exec(ctx, "UPDATE gauth_user_verification SET isverified=$1 WHERE user_id=$2", isVerified, userid)
	return err
}

func (s *PostgresDB) GetIsverified(ctx context.Context, userid uuid.UUID) (bool, error) {
	var isVerified bool
	err := s.Pool.QueryRow(ctx, "SELECT isverified FROM gauth_user_verification WHERE user_id=$1", userid).Scan(&isVerified)
	if err != nil {
		return false, err
	}
	return isVerified, nil
}

func (s *PostgresDB) SetUserVerificationDetails(ctx context.Context, userid uuid.UUID, verificationType, verficationItem, token string, duration time.Duration) error {
	_, err := s.Pool.Exec(ctx, "UPDATE gauth_user_verification SET verification_token=$1, token_expiry=$2, verification_type=$3, verificaton_item=$4 WHERE user_id=$5", token, time.Now().Add(duration), verificationType, verficationItem, userid)
	return err
}

func (s *PostgresDB) GetUserVerificationDetails(ctx context.Context, verificationToken string) (verificationType string, verficationItem string, userID uuid.UUID, expiry time.Time, err error) {
	var tduration time.Time
	var id uuid.UUID
	var t string
	var item string
	err = s.Pool.QueryRow(ctx, "SELECT user_id ,token_expiry, verification_type, verificaton_item FROM gauth_user_verification WHERE verification_token=$1", verificationToken).Scan(&id, &tduration, &t, &item)
	return t, item, id, tduration, err
}

func (s *PostgresDB) GetUsername(ctx context.Context, userid uuid.UUID) (string, error) {
	var oUsername string
	err := s.Pool.QueryRow(ctx, "SELECT username FROM gauth_user WHERE id=$1", userid).Scan(&oUsername)
	return oUsername, err
}

func (s *PostgresDB) SetUsername(ctx context.Context, userid uuid.UUID, newUsername string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, "UPDATE gauth_user SET username=$1 WHERE id=$2", newUsername, userid)
	if err != nil {
		tx.Rollback(ctx)
		if strings.Contains(err.Error(), "23505") {
			return errs.ErrDuplicateKey
		}
	}

	_, err = tx.Exec(ctx, "UPDATE gauth_user_auth SET last_username_change=$1 WHERE user_id=$2", time.Now(), userid)
	if err != nil {
		tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

func (s *PostgresDB) SetFingerprint(ctx context.Context, userid uuid.UUID, fingerprint string) error {
	_, err := s.Pool.Exec(ctx, "UPDATE gauth_user_auth SET login_fingerprint=$1 WHERE user_id=$2", fingerprint, userid)
	return err
}

func (s *PostgresDB) GetFingerprint(ctx context.Context, userid uuid.UUID) (string, error) {
	var fingerprint string
	err := s.Pool.QueryRow(ctx, "SELECT login_fingerprint FROM gauth_user_auth WHERE user_id=$1", userid).Scan(&fingerprint)
	return fingerprint, err
}

func (s *PostgresDB) SetSignupMethod(ctx context.Context, userid uuid.UUID, method string) error {
	_, err := s.Pool.Exec(ctx, "UPDATE gauth_user SET signup_method=$1 WHERE id=$2", method, userid)
	return err
}

func (s *PostgresDB) GetSignupMethod(ctx context.Context, userid uuid.UUID) (string, error) {
	var method string
	err := s.Pool.QueryRow(ctx, "SELECT signup_method FROM gauth_user WHERE id=$1", userid).Scan(&method)
	return method, err
}

func (s *PostgresDB) SetUserImage(ctx context.Context, userid uuid.UUID, base64Image []byte) error {
	_, err := s.Pool.Exec(ctx, "UPDATE gauth_user SET profile_picture=$1 WHERE id=$2", base64Image, userid)
	return err
}

func (s *PostgresDB) GetUserImage(ctx context.Context, userid uuid.UUID) ([]byte, error) {
	var base64Image []byte
	err := s.Pool.QueryRow(ctx, "SELECT profile_picture FROM gauth_user WHERE id=$1", userid).Scan(&base64Image)
	return base64Image, err
}
