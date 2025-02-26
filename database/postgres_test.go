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

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    birth_date DATE,
    address TEXT,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'user', 'moderator', 'guest')), -- Customizable roles
    password_hash TEXT NOT NULL,
    last_login TIMESTAMP NULL,
    phone_number VARCHAR(20) DEFAULT NULL,
    auth_provider VARCHAR(50) DEFAULT NULL,
    auth_id VARCHAR(255) DEFAULT NULL,
    refresh_token TEXT DEFAULT NULL,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_password_change TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    two_factor_secret TEXT DEFAULT NULL,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    profile_picture TEXT DEFAULT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'deleted')),
    metadata JSON DEFAULT '{}',
    preferences JSONB DEFAULT '{}'
);
	`)

	if err != nil {
		clean()
		return nil, nil, fmt.Errorf("failed to create users table: %v", err)
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

	db := PostgresDB{pool: conn}

	username := "jack"
	email := "jack@gmail.com"
	password := "lsijdblrhaeliurlkjehj34j3h!@#$#"

	uuid, err := db.AddUser(context.Background(), username, email, "user", password)
	if err != nil {
		t.Fatal(err)
	}

	var dbusername, dbemail, dbrole, dbpassword string
	err = conn.QueryRow(context.Background(), "SELECT username, email, role, password_hash FROM users WHERE id=$1", uuid).Scan(&dbusername, &dbemail, &dbrole, &dbpassword)
	if err != nil {
		t.Fatal(err)
	}

	if dbusername != username {
		t.Error("username in database doesnt match")
	}

	if dbemail != email {
		t.Error("emaidbemail database doesnt match")
	}

	if dbpassword != password {
		t.Error("password in database doesnt match")
	}

	if dbrole != "user" {
		t.Error("username in database doesnt match")
	}
}
