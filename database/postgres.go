package database

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	errs "github.com/scott-mescudi/gauth/shared/errors"
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

func (s *PostgresDB) AddUser(ctx context.Context, username, email, role, passwordHash string) (uuid.UUID, error) {
	var uid uuid.UUID

	err := s.pool.QueryRow(ctx, `INSERT INTO gauth_users (username, email, role, password_hash) VALUES ($1, $2, $3, $4) RETURNING id`, username, email, role, passwordHash).Scan(&uid)
	if err != nil {
		return uuid.Nil, err
	}

	return uid, nil
}

func (s *PostgresDB) GetUserPasswordAndIDByEmail(ctx context.Context, email string) (userID uuid.UUID, passwordHash string, err error) {
	var (
		uid          uuid.UUID
		passwordhash string
	)
	err = s.pool.QueryRow(ctx, "SELECT password_hash, id FROM gauth_users WHERE email=$1", email).Scan(&passwordhash, &uid)
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
	err = s.pool.QueryRow(ctx, "SELECT password_hash, id FROM gauth_users WHERE username=$1", username).Scan(&passwordhash, &uid)
	if err != nil {
		return uuid.Nil, "", err
	}

	return uid, passwordhash, nil
}

func (s *PostgresDB) SetUserFields(ctx context.Context, uuid uuid.UUID, fields *GauthUserFields) error {
	return nil
}
func (s *PostgresDB) GetUserFields(ctx context.Context, uuid uuid.UUID) (fields *GauthUserFields, err error) {
	return nil, nil
}

func (s *PostgresDB) SetRefreshToken(ctx context.Context, token string, userid uuid.UUID) error {
	_, err := s.pool.Exec(ctx, "UPDATE gauth_users SET refresh_token=$1 WHERE id=$2", token, userid)
	return err
}

func (s *PostgresDB) GetRefreshToken(ctx context.Context, userid uuid.UUID) (string, error) {
	var token string
	err := s.pool.QueryRow(ctx, "SELECT refresh_token FROM gauth_users WHERE id=$1", userid).Scan(&token)
	return token, err
}

func (s *PostgresDB) UpdateUserPassword(ctx context.Context, userid uuid.UUID, newPassword string) error {
	_, err := s.pool.Exec(ctx, "UPDATE gauth_users SET password_hash=$1 WHERE id=$2", newPassword, userid)
	return err
}

func (s *PostgresDB) DeleteUser(ctx context.Context, userid uuid.UUID) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM gauth_users WHERE user_id=$1", userid)
	return err
}

func (s *PostgresDB) SetUserProfilePicture(ctx context.Context, userid uuid.UUID, profilePicture string) error {
	_, err := s.pool.Exec(ctx, "UPDATE gauth_users SET profile_picture=$1 WHERE id=$2", profilePicture, userid)
	return err
}

func (s *PostgresDB) GetUserProfilePicture(ctx context.Context, userid uuid.UUID) (string, error) {
	var profilePicture string
	err := s.pool.QueryRow(ctx, "SELECT profile_picture FROM gauth_users WHERE id=$1", userid).Scan(&profilePicture)
	return profilePicture, err
}

func (s *PostgresDB) SetUserName(ctx context.Context, userid uuid.UUID, firstName, lastName string) error {
	_, err := s.pool.Exec(ctx, "UPDATE gauth_users SET first_name=$1, last_name=$2 WHERE id=$3", firstName, lastName, userid)
	return err
}

func (s *PostgresDB) SetUserEmail(ctx context.Context, userid uuid.UUID, email string) error {
	_, err := s.pool.Exec(ctx, "UPDATE gauth_users SET email=$1 WHERE id=$2", email, userid)
	return err
}
