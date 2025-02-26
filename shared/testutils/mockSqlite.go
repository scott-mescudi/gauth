package database

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

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

	_, err = db.Exec(`
CREATE TABLE gauth_users (
    id TEXT PRIMARY KEY NOT NULL UNIQUE,
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
    preferences TEXT DEFAULT '{}',
    metadata TEXT DEFAULT '{}'
);
	`)

	if err != nil {
		clean()
		return nil, nil, fmt.Errorf("failed create table gauth_users: %v", err)
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
