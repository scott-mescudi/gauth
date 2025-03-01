package database

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type DB interface {
	Ping(ctx context.Context) error
	Close()
	AddUser(ctx context.Context, username, email, role, passwordHash string, isVerified bool) (uuid.UUID, error)
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
}

type Config struct {
	MaxConns        int
	MinConns        int
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

type GauthUserFields struct {
	FirstName        string     `json:"first_name" db:"first_name"`
	LastName         string     `json:"last_name" db:"last_name"`
	BirthDate        *time.Time `json:"birth_date" db:"birth_date"`
	Address          string     `json:"address" db:"address"`
	Role             string     `json:"role" db:"role"`
	LastLogin        *time.Time `json:"last_login" db:"last_login"`
	PhoneNumber      string     `json:"phone_number" db:"phone_number"`
	AuthProvider     string     `json:"auth_provider" db:"auth_provider"`
	AuthID           string     `json:"auth_id" db:"auth_id"`
	Created          time.Time  `json:"created" db:"created"`
	Updated          time.Time  `json:"updated" db:"updated"`
	TwoFactorSecret  string     `json:"two_factor_secret" db:"two_factor_secret"`
	TwoFactorEnabled bool       `json:"two_factor_enabled" db:"two_factor_enabled"`
	Status           string     `json:"status" db:"status"`
	Metadata         string     `json:"metadata" db:"metadata"`
	Preferences      string     `json:"preferences" db:"preferences"`
}
