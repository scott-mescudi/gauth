package database

import (
	"context"
	"fmt"

	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var postgrestable = `
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
    verification_item TEXT,
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

func SetupTestPostgresDBConnStr(testData string) (string, func(), error) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx, "postgres:latest",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testAdmin"),
		postgres.WithPassword("pass1234"))
	if err != nil {
		return "", nil, fmt.Errorf("failed to start PostgreSQL container: %v", err)
	}

	time.Sleep(3 * time.Second)

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgContainer.Terminate(ctx)
		return "", nil, fmt.Errorf("failed to get PostgreSQL connection string: %v", err)
	}

	conn, err := pgxpool.New(ctx, connStr)
	if err != nil {
		pgContainer.Terminate(ctx)
		return "", nil, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}

	defer conn.Close()

	_, err = conn.Exec(ctx, postgrestable)
	if err != nil {
		pgContainer.Terminate(ctx)
		return "", nil, fmt.Errorf("failed to execute queries: %v", err)
	}

	if testData != "" {
		_, err = conn.Exec(ctx, postgrestable)
		if err != nil {
			pgContainer.Terminate(ctx)
			return "", nil, fmt.Errorf("failed to insert test data: %v", err)
		}
	}

	clean := func() {
		pgContainer.Terminate(ctx)
	}

	return connStr, clean, nil
}

func SetupTestPostgresDB(testData string) (*pgxpool.Pool, func(), error) {
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

	conn, err := pgxpool.New(context.Background(), str)
	if err != nil {
		return nil, nil, err
	}
	clean := func() {
		conn.Close()
		pgContainer.Terminate(ctx)
	}

	_, err = conn.Exec(ctx, postgrestable)

	if err != nil {
		clean()
		return nil, nil, fmt.Errorf("failed to create gauth_user table: %v", err)
	}

	if testData != "" {
		_, err = conn.Exec(ctx, testData)
		if err != nil {
			clean()
			return nil, nil, fmt.Errorf("failed to create test data: %v", err)
		}
	}

	return conn, clean, nil
}
