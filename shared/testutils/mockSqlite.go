package database

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var sqlitetable = `
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

func SetupTestSqliteDBConnStr(testData string) (string, func(), error) {
	dbName := "testing.sqlite"
	db, err := sql.Open("sqlite3", dbName)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open database: %w", err)
	}
	time.Sleep(3 * time.Second)

	if err := db.Ping(); err != nil {
		db.Close()
		return "", nil, fmt.Errorf("failed to establish a database connection: %w", err)
	}

	_, err = db.Exec(sqlitetable)
	if err != nil {
		db.Close()
		return "", nil, fmt.Errorf("failed to execute queries: %w", err)
	}

	if testData != "" {
		_, err = db.Exec(testData)
		if err != nil {
			db.Close()
			return "", nil, fmt.Errorf("failed to insert test data: %w", err)
		}
	}
	db.Close()

	clean := func() {
		time.Sleep(1 * time.Second)
		if err := os.Remove(dbName); err != nil {
			fmt.Printf("Warning: failed to remove database file: %v\n", err)
		}
	}

	return dbName, clean, nil
}

func SetupTestSqliteDB(testData string) (*sql.DB, func(), error) {
	dbName := "testing.sqlite"
	db, err := sql.Open("sqlite3", dbName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open in memory database")
	}

	time.Sleep(3 * time.Second)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("failed to establish a database connection: %w", err)
	}

	clean := func() {
		db.Close()
		time.Sleep(1 * time.Second)
		if err := os.Remove(dbName); err != nil {
			fmt.Printf("Warning: failed to remove database file: %v\n", err)
		}
	}

	_, err = db.Exec(sqlitetable)

	if err != nil {
		clean()
		return nil, nil, fmt.Errorf("failed create table gauth_user: %v", err)
	}

	if testData != "" {
		_, err = db.Exec(testData)
		if err != nil {
			clean()
			return nil, nil, fmt.Errorf("failed to create test data: %v", err)
		}
	}

	return db, clean, err

}
