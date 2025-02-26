package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestSqliteDB(testData string) (*sql.DB, func(), error) {
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
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    birth_date DATE,
    address TEXT,
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'user', 'moderator', 'guest')),
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
    metadata TEXT DEFAULT '{}',  
    preferences TEXT DEFAULT '{}' 
);

	`)

	if err != nil {
		clean()
		return nil, nil, fmt.Errorf("failed create table users: %v", err)
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

func TestAddUserSqlite(t *testing.T) {
	conn, clean, err := setupTestSqliteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := SqliteDB{db: conn}

	username := "jack"
	email := "jack@gmail.com"
	password := "lsijdblrhaeliurlkjehj34j3h!@#$#"

	uuid, err := db.AddUser(context.Background(), username, email, "user", password)
	if err != nil {
		t.Fatal(err)
	}

	var dbusername, dbemail, dbrole, dbpassword string
	err = conn.QueryRowContext(context.Background(), "SELECT username, email, role, password_hash FROM users WHERE id=?", uuid.String()).Scan(&dbusername, &dbemail, &dbrole, &dbpassword)
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

func TestGetUserPasswordAndIDByEmailSqlite(t *testing.T) {
	conn, clean, err := setupTestSqliteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := SqliteDB{db: conn}

	uuid, err := db.AddUser(t.Context(), "jack", "jack@jack.com", "user", "password123")
	if err != nil {
		t.Fatal(err)
	}


	userid, passwordHash, err := db.GetUserPasswordAndIDByEmail(t.Context(), "jack@jack.com")
	if err != nil {
		t.Fatal(err)
	}

	if userid.String() != uuid.String() {
		t.Fatal("uuids dont match")
	}

	if passwordHash != "password123" {
		t.Fatal("passwords dont match")
	}
}

func TestGetUserPasswordAndIDByUsernameSqlite(t *testing.T) {
	conn, clean, err := setupTestSqliteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := SqliteDB{db: conn}

	uuid, err := db.AddUser(t.Context(), "jack", "jack@jack.com", "user", "password123")
	if err != nil {
		t.Fatal(err)
	}


	userid, passwordHash, err := db.GetUserPasswordAndIDByUsername(t.Context(), "jack")
	if err != nil {
		t.Fatal(err)
	}

	if userid.String() != uuid.String() {
		t.Fatal("uuids dont match")
	}

	if passwordHash != "password123" {
		t.Fatal("passwords dont match")
	}
}
