package database

import (
	"context"
	"fmt"

	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func setupTestPostgresDB(testData string) (*pgxpool.Pool, func(), error) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx, "postgres:latest", postgres.WithDatabase("testdb"), postgres.WithUsername("testAdmin"), postgres.WithPassword("pass1234"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to start PostgreSQL container: %v", err)
	}

	time.Sleep(3 * time.Second)

	str, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get PostgreSQL uri: %v", err)
	}

	conn, err := NewPostgresDB(str, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to PostgreSQL DB: %v", err)
	}

	clean := func() {
		conn.Close()
		pgContainer.Terminate(ctx)
	}

	_, err = conn.pool.Exec(ctx, `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE gauth_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    birth_date DATE,
    address TEXT,
    profile_picture TEXT DEFAULT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'user', 'moderator', 'guest')),
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'deleted', 'disabled')),
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE gauth_user_auth (
    user_id UUID PRIMARY KEY REFERENCES gauth_users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    last_login TIMESTAMP NULL,
    last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    auth_provider VARCHAR(50) DEFAULT NULL,
    auth_id VARCHAR(255) DEFAULT NULL,
    refresh_token TEXT DEFAULT NULL,
    two_factor_secret TEXT DEFAULT NULL,
    two_factor_enabled BOOLEAN DEFAULT FALSE
);

CREATE TABLE gauth_user_preferences (
    user_id UUID PRIMARY KEY REFERENCES gauth_users(id) ON DELETE CASCADE,
    preferences JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}'
);
	`)

	if err != nil {
		clean()
		return nil, nil, fmt.Errorf("failed to create gauth_users table: %v", err)
	}

	if testData != "" {
		_, err = conn.pool.Exec(ctx, testData)
		if err != nil {
			clean()
			return nil, nil, fmt.Errorf("failed to create test data: %v", err)
		}
	}

	return conn.pool, clean, nil
}

func TestAddUserPostgres(t *testing.T) {
	conn, clean, err := setupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{pool: conn}

	username := "jack"
	email := "jack@gmail.com"
	password := "securepassword123"
	role := "user"

	uuid, err := db.AddUser(t.Context(), username, email, role, password)
	if err != nil {
		t.Fatalf("error in function: %v",err)
	}

	var dbusername, dbemail, dbrole string
	err = conn.QueryRow(t.Context(), "SELECT username, email, role FROM gauth_users WHERE id=$1", uuid).Scan(&dbusername, &dbemail, &dbrole)
	if err != nil {
		t.Fatal(err)
	}

	if dbusername != username {
		t.Error("username in database doesn't match")
	}

	if dbemail != email {
		t.Error("email in database doesn't match")
	}

	if dbrole != role {
		t.Error("role in database doesn't match")
	}
}

func TestGetUserPasswordAndIDByEmailPostgres(t *testing.T) {
	conn, clean, err := setupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{pool: conn}

	uuid, err := db.AddUser(t.Context(), "jack", "jack@jack.com", "user", "password123")
	if err != nil {
		t.Fatal(err)
	}

	userid, passwordHash, err := db.GetUserPasswordAndIDByEmail(t.Context(), "jack@jack.com")
	if err != nil {
		t.Fatalf("error in function: %v",err)
	}

	if userid.String() != uuid.String() {
		t.Fatal("UUIDs don't match")
	}

	var storedHash string
	err = conn.QueryRow(t.Context(), "SELECT password_hash FROM gauth_user_auth WHERE user_id=$1", uuid).Scan(&storedHash)
	if err != nil {
		t.Fatal(err)
	}

	if storedHash != passwordHash {
		t.Fatal("password hashes don't match")
	}
}

func TestGetUserPasswordAndIDByUsernamePostgres(t *testing.T) {
	conn, clean, err := setupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{pool: conn}

	uuid, err := db.AddUser(t.Context(), "jack", "jack@jack.com", "user", "password123")
	if err != nil {
		t.Fatal(err)
	}

	userid, passwordHash, err := db.GetUserPasswordAndIDByUsername(t.Context(), "jack")
	if err != nil {
		t.Fatalf("error in function: %v",err)
	}

	if userid.String() != uuid.String() {
		t.Fatal("uuids dont match")
	}

	if passwordHash != "password123" {
		t.Fatal("passwords dont match")
	}
}

func TestSetRefreshTokenPostgres(t *testing.T) {
	conn, clean, err := setupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{pool: conn}

	uuid, err := db.AddUser(t.Context(), "jack", "jack@jack.com", "user", "password123")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.SetRefreshToken(t.Context(), "token123", uuid); err != nil {
		t.Fatalf("error in function: %v",err)
	}

	var token string
	err = conn.QueryRow(t.Context(), "SELECT refresh_token FROM gauth_user_auth WHERE user_id=$1", uuid).Scan(&token)
	if err != nil {
		t.Fatal(err)
	}

	if token != "token123" {
		t.Fatal("refresh token mismatch")
	}
}


func TestGetRefreshTokenPostgres(t *testing.T) {
	conn, clean, err := setupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{pool: conn}

	uuid, err := db.AddUser(t.Context(), "jack", "jack@jack.com", "user", "password123")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.SetRefreshToken(t.Context(), "token 123", uuid); err != nil {
		t.Fatal(err)
	}

	token, err := db.GetRefreshToken(t.Context(), uuid)
	if err != nil {
		t.Fatalf("error in function: %v",err)
	}

	if token != "token 123" {
		t.Fatal("got invalid token")
	}
}
