package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type DB interface {
	Ping(ctx context.Context) error
	Close()
	Migrate()
	AddUser(ctx context.Context, fname, lname, username, email, role, passwordHash string, isVerified bool) (uuid.UUID, error)
	GetUserPasswordAndIDByEmail(ctx context.Context, email string) (userID uuid.UUID, passwordHash string, err error)
	GetUserPasswordAndIDByUsername(ctx context.Context, username string) (userID uuid.UUID, passwordHash string, err error)
	SetRefreshToken(ctx context.Context, token string, userid uuid.UUID) error
	GetRefreshToken(ctx context.Context, userid uuid.UUID) (string, error)
	DeleteUser(ctx context.Context, userid uuid.UUID) error
	GetUserPasswordByID(ctx context.Context, userid uuid.UUID) (string, error)
	SetUserPassword(ctx context.Context, userid uuid.UUID, newPassword string) error
	SetUserEmail(ctx context.Context, userid uuid.UUID, newEmail string) error
	GetUserEmail(ctx context.Context, userid uuid.UUID) (string, error)
	SetIsverified(ctx context.Context, userid uuid.UUID, isVerified bool) error
	GetIsverified(ctx context.Context, userid uuid.UUID) (bool, error)
	GetUserVerificationDetails(ctx context.Context, verificationToken string) (verificationType string, verficationItem string, userID uuid.UUID, expiry time.Time, err error)
	SetUserVerificationDetails(ctx context.Context, userid uuid.UUID, verificationType, verficationItem, token string, duration time.Duration) error
	GetUsername(ctx context.Context, userid uuid.UUID) (string, error)
	SetUsername(ctx context.Context, userid uuid.UUID, newUsername string) error
	SetFingerprint(ctx context.Context, userid uuid.UUID, fingerprint string) error
	GetFingerprint(ctx context.Context, userid uuid.UUID) (string, error)
	SetSignupMethod(ctx context.Context, userid uuid.UUID, method string) error
	GetSignupMethod(ctx context.Context, userid uuid.UUID) (string, error)
	SetUserImage(ctx context.Context, userid uuid.UUID, base64Image []byte) error
	GetUserImage(ctx context.Context, userid uuid.UUID) ([]byte, error)
	GetUserDetails(ctx context.Context, userid uuid.UUID) (
		Username string,
		Email string,
		FirstName string,
		LastName string,
		SignupMethod string,
		Role string,
		Created time.Time,
		LastLogin sql.NullTime,
		err error,
	)
	GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error)
}

type Config struct {
	MaxConns        int
	MinConns        int
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}
