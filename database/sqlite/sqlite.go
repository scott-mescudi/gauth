package database

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
)

var postgresSchema = `
CREATE TABLE gauth_user (
    id TEXT PRIMARY KEY NOT NULL UNIQUE,
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

type SqliteDB struct {
	Pool *sql.DB
}

func (s *SqliteDB) Migrate() {
	s.Pool.ExecContext(context.Background(), postgresSchema)
}

func (s *SqliteDB) Ping(ctx context.Context) error {
	return s.Pool.PingContext(ctx)
}

func (s *SqliteDB) Close() {
	s.Pool.Close()
}

func (s *SqliteDB) AddUser(ctx context.Context, fname, lname, username, email, role, passwordHash string, isVerified bool) (uuid.UUID, error) {
	var uid uuid.UUID = uuid.New()
	tx, err := s.Pool.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO gauth_user (id, username, email, role, first_name, last_name) VALUES (?, ?, ?, ?, ?, ?)`, uid.String(), username, strings.ToLower(email), role, fname, lname)
	if err != nil {
		tx.Rollback()
		if strings.Contains(err.Error(), "23505") {
			return uuid.Nil, errs.ErrDuplicateKey
		}
		return uuid.Nil, err
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO gauth_user_auth (password_hash, user_id) VALUES (?, ?)", passwordHash, uid)
	if err != nil {
		tx.Rollback()
		return uuid.Nil, err
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO gauth_user_verification (user_id, isverified) VALUES (?, ?)", uid, isVerified)
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

	err = s.Pool.QueryRowContext(ctx, "SELECT gua.password_hash, gu.id FROM gauth_user gu JOIN gauth_user_auth gua ON gu.id = gua.user_id WHERE gu.email=?", strings.ToLower(email)).Scan(&passwordhash, &uidStr)
	if err != nil {
		return uuid.Nil, "", err
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		return uuid.Nil, "", err
	}

	return uid, passwordhash, nil
}

func (s *SqliteDB) GetUserPasswordAndIDByUsername(ctx context.Context, username string) (userID uuid.UUID, passwordHash string, err error) {
	var (
		uidStr       string
		passwordhash string
	)
	err = s.Pool.QueryRowContext(ctx, "SELECT gua.password_hash, gu.id FROM gauth_user gu JOIN gauth_user_auth gua ON gu.id = gua.user_id WHERE gu.username=?", username).Scan(&passwordhash, &uidStr)
	if err != nil {
		return uuid.Nil, "", err
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		return uuid.Nil, "", err
	}

	return uid, passwordhash, nil
}

func (s *SqliteDB) SetRefreshToken(ctx context.Context, token string, userid uuid.UUID) error {
	_, err := s.Pool.ExecContext(ctx, "UPDATE gauth_user_auth SET refresh_token=? WHERE user_id=?", token, userid.String())
	return err
}

func (s *SqliteDB) GetRefreshToken(ctx context.Context, userid uuid.UUID) (string, error) {
	var token string
	err := s.Pool.QueryRowContext(ctx, "SELECT refresh_token FROM gauth_user_auth WHERE user_id=?", userid.String()).Scan(&token)
	return token, err
}

func (s *SqliteDB) SetUserPassword(ctx context.Context, userid uuid.UUID, newPassword string) error {
	tx, err := s.Pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE gauth_user_auth SET password_hash=? WHERE user_id=?", newPassword, userid.String())
	if err != nil {
		tx.Rollback()
		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE gauth_user_auth SET last_password_change=? WHERE user_id=?", time.Now(), userid.String())
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (s *SqliteDB) DeleteUser(ctx context.Context, userid uuid.UUID) error {
	tx, err := s.Pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM gauth_user WHERE id=?", userid)
	if err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (s *SqliteDB) GetUserPasswordByID(ctx context.Context, userid uuid.UUID) (string, error) {
	var passwordHash string
	err := s.Pool.QueryRowContext(context.Background(), "SELECT password_hash from gauth_user_auth WHERE user_id=?", userid).Scan(&passwordHash)
	return passwordHash, err
}

func (s *SqliteDB) SetUserEmail(ctx context.Context, userid uuid.UUID, newEmail string) error {
	tx, err := s.Pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE gauth_user SET email=? WHERE id=?", strings.ToLower(newEmail), userid)
	if err != nil {
		tx.Rollback()
		if strings.Contains(err.Error(), "23505") {
			return errs.ErrDuplicateKey
		}

		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE gauth_user_auth SET last_email_change=? WHERE user_id=?", time.Now(), userid)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (s *SqliteDB) GetUserEmail(ctx context.Context, userid uuid.UUID) (string, error) {
	var op string
	err := s.Pool.QueryRowContext(ctx, "SELECT email FROM gauth_user WHERE id=?", userid).Scan(&op)
	return op, err
}

func (s *SqliteDB) SetIsverified(ctx context.Context, userid uuid.UUID, isVerified bool) error {
	_, err := s.Pool.ExecContext(ctx, "UPDATE gauth_user_verification SET isverified=? WHERE user_id=?", isVerified, userid)
	return err
}

func (s *SqliteDB) GetIsverified(ctx context.Context, userid uuid.UUID) (bool, error) {
	var isVerified bool
	err := s.Pool.QueryRowContext(ctx, "SELECT isverified FROM gauth_user_verification WHERE user_id=?", userid).Scan(&isVerified)
	if err != nil {
		return false, err
	}
	return isVerified, nil
}

func (s *SqliteDB) SetUserVerificationDetails(ctx context.Context, userid uuid.UUID, verificationType, verficationItem, token string, duration time.Duration) error {
	_, err := s.Pool.ExecContext(ctx, "UPDATE gauth_user_verification SET verification_token=?, token_expiry=?, verification_type=?, verificaton_item=? WHERE user_id=?", token, time.Now().Add(duration), verificationType, verficationItem, userid)
	return err
}

func (s *SqliteDB) GetUserVerificationDetails(ctx context.Context, verificationToken string) (verificationType string, verficationItem string, userID uuid.UUID, expiry time.Time, err error) {
	var tduration time.Time
	var id uuid.UUID
	var t string
	var item string
	err = s.Pool.QueryRowContext(ctx, "SELECT user_id ,token_expiry, verification_type, verificaton_item FROM gauth_user_verification WHERE verification_token=?", verificationToken).Scan(&id, &tduration, &t, &item)
	return t, item, id, tduration, err
}

func (s *SqliteDB) GetUsername(ctx context.Context, userid uuid.UUID) (string, error) {
	var oUsername string
	err := s.Pool.QueryRowContext(ctx, "SELECT username FROM gauth_user WHERE id=?", userid).Scan(&oUsername)
	return oUsername, err
}

func (s *SqliteDB) SetUsername(ctx context.Context, userid uuid.UUID, newUsername string) error {
	tx, err := s.Pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE gauth_user SET username=? WHERE id=?", newUsername, userid)
	if err != nil {
		tx.Rollback()
		if strings.Contains(err.Error(), "23505") {
			return errs.ErrDuplicateKey
		}
	}

	_, err = tx.ExecContext(ctx, "UPDATE gauth_user_auth SET last_username_change=? WHERE user_id=?", time.Now(), userid)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (s *SqliteDB) SetFingerprint(ctx context.Context, userid uuid.UUID, fingerprint string) error {
	_, err := s.Pool.ExecContext(ctx, "UPDATE gauth_user_auth SET login_fingerprint=? WHERE user_id=?", fingerprint, userid)
	return err
}

func (s *SqliteDB) GetFingerprint(ctx context.Context, userid uuid.UUID) (string, error) {
	var fingerprint sql.NullString
	err := s.Pool.QueryRowContext(ctx, "SELECT login_fingerprint FROM gauth_user_auth WHERE user_id=?", userid).Scan(&fingerprint)
	return fingerprint.String, err
}

func (s *SqliteDB) SetSignupMethod(ctx context.Context, userid uuid.UUID, method string) error {
	_, err := s.Pool.ExecContext(ctx, "UPDATE gauth_user SET signup_method=? WHERE id=?", method, userid)
	return err
}

func (s *SqliteDB) GetSignupMethod(ctx context.Context, userid uuid.UUID) (string, error) {
	var method string
	err := s.Pool.QueryRowContext(ctx, "SELECT signup_method FROM gauth_user WHERE id=?", userid).Scan(&method)
	return method, err
}

func (s *SqliteDB) SetUserImage(ctx context.Context, userid uuid.UUID, base64Image []byte) error {
	_, err := s.Pool.ExecContext(ctx, "UPDATE gauth_user SET profile_picture=? WHERE id=?", base64Image, userid)
	return err
}

func (s *SqliteDB) GetUserImage(ctx context.Context, userid uuid.UUID) ([]byte, error) {
	var base64Image []byte
	err := s.Pool.QueryRowContext(ctx, "SELECT profile_picture FROM gauth_user WHERE id=?", userid).Scan(&base64Image)
	return base64Image, err
}

func (s *SqliteDB) GetUserDetails(ctx context.Context, userid uuid.UUID) (
	Username string,
	Email string,
	FirstName string,
	LastName string,
	SignupMethod string,
	Role string,
	Created time.Time,
	LastLogin sql.NullTime,
	err error,
) {

	err = s.Pool.QueryRowContext(ctx, "SELECT gu.username, gu.email, gu.first_name, gu.last_name, gu.signup_method, gu.role, gu.created, gua.last_login FROM gauth_user gu JOIN gauth_user_auth gua ON gu.id = gua.user_id WHERE gu.id=?", userid).Scan(
		&Username,
		&Email,
		&FirstName,
		&LastName,
		&SignupMethod,
		&Role,
		&Created,
		&LastLogin,
	)

	return
}

func (s *SqliteDB) GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	var uid uuid.UUID
	err := s.Pool.QueryRowContext(ctx, "SELECT id FROM gauth_user where email=?", email).Scan(&uid)
	return uid, err
}

func (s *SqliteDB) UserExists(ctx context.Context, username string) bool {
	var exists bool
	err := s.Pool.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM gauth_user WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return false
	}

	return exists
}

func (s *SqliteDB) UserExistsByEmail(ctx context.Context, email string) bool {
	var exists bool
	err := s.Pool.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM gauth_user WHERE email = ?)", email).Scan(&exists)
	if err != nil {
		return false
	}

	return exists
}
