package database

import (
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

func TestAddUserSqlite(t *testing.T) {
	conn, clean, err := setupTestSqliteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &SqliteDB{db: conn}

	username := "jack"
	email := "jack@gmail.com"
	password := "lsijdblrhaeliurlkjehj34j3h!@#$#"
	role := "user"

	uuid, err := db.AddUser(t.Context(), username, email, role, password)
	if err != nil {
		t.Fatalf("error in function: %v",err)
	}

	var dbusername, dbemail, dbrole string
	err = conn.QueryRowContext(t.Context(), "SELECT username, email, role FROM gauth_users WHERE id=$1", uuid).Scan(&dbusername, &dbemail, &dbrole)
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

func TestGetUserPasswordAndIDByEmailSqlite(t *testing.T) {
	conn, clean, err := setupTestSqliteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &SqliteDB{db: conn}

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

	db := &SqliteDB{db: conn}

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

func TestSetRefreshTokenSqlite(t *testing.T) {
	conn, clean, err := setupTestSqliteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &SqliteDB{db: conn}

	uuid, err := db.AddUser(t.Context(), "jack", "jack@jack.com", "user", "password123")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.SetRefreshToken(t.Context(), "token 123", uuid); err != nil {
		t.Fatal(err)
	}

	var token string
	err = conn.QueryRowContext(t.Context(), "SELECT gua.refresh_token FROM gauth_user_auth gua JOIN gauth_users gu ON gua.user_id = gu.id WHERE gu.username='jack'").Scan(&token)
	if err != nil {
		t.Fatal(err)
	}

	if token == "" {
		t.Fatal("token is empty")
	}
}

func TestGetRefreshTokenSqlite(t *testing.T) {
	conn, clean, err := setupTestSqliteDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &SqliteDB{db: conn}

	uuid, err := db.AddUser(t.Context(), "jack", "jack@jack.com", "user", "password123")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.SetRefreshToken(t.Context(), "token 123", uuid); err != nil {
		t.Fatal(err)
	}

	token, err := db.GetRefreshToken(t.Context(), uuid)
	if err != nil {
		t.Fatal(err)
	}

	if token != "token 123" {
		t.Fatal("got invalid token")
	}
}
