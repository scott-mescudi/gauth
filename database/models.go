package database

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type DB interface {
    Ping(ctx context.Context) error
    Close()
    AddUser(ctx context.Context, username, email, role, passwordHash string) (uuid.UUID, error)
    GetUserPasswordAndIDByEmail(ctx context.Context, email string) (userID uuid.UUID, passwordHash string, err error)
    GetUserPasswordAndIDByUsername(ctx context.Context, username string) (userID uuid.UUID, passwordHash string, err error)
    SetRefreshToken(ctx context.Context, token string, userid uuid.UUID) error
    GetRefreshToken(ctx context.Context, userid uuid.UUID) (string, error)
    SetUserMetadata(ctx context.Context, userid uuid.UUID, metadata string) error
    GetUserMetadata(ctx context.Context, userid uuid.UUID) (string, error)
    SetUserPreferences(ctx context.Context, userid uuid.UUID, preferences string) error
    GetUserPreferences(ctx context.Context, userid uuid.UUID) (string, error)
    SetUserProfilePicture(ctx context.Context, userid uuid.UUID, profilePicture string) error
    GetUserProfilePicture(ctx context.Context, userid uuid.UUID) (string, error)
    SetUserName(ctx context.Context, userid uuid.UUID, firstName, lastName string) error
    SetUserEmail(ctx context.Context, userid uuid.UUID, email string) error
    SetUserAddress(ctx context.Context, userid uuid.UUID, address string) error
    SetUserPhoneNumber(ctx context.Context, userid uuid.UUID, phoneNumber string) error
    SetUserRole(ctx context.Context, userid uuid.UUID, role string) error
    SetUserBirthDate(ctx context.Context, userid uuid.UUID, birthDate string) error
    SetUserStatus(ctx context.Context, userid uuid.UUID, status string) error
    SetTwoFactorSecret(ctx context.Context, userid uuid.UUID, secret string) error
}


type Config struct {
	MaxConns        int
	MinConns        int
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}
