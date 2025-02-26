package database

import (
	_ "github.com/lib/pq"
	tu "github.com/scott-mescudi/gauth/shared/testutils"
	"testing"
)

func TestAddUserPostgres(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
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
		t.Fatalf("error in function: %v", err)
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
	conn, clean, err := tu.SetupTestPostgresDB("")
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
		t.Fatalf("error in function: %v", err)
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
	conn, clean, err := tu.SetupTestPostgresDB("")
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
		t.Fatalf("error in function: %v", err)
	}

	if userid.String() != uuid.String() {
		t.Fatal("uuids dont match")
	}

	if passwordHash != "password123" {
		t.Fatal("passwords dont match")
	}
}

func TestSetRefreshTokenPostgres(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
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
		t.Fatalf("error in function: %v", err)
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
	conn, clean, err := tu.SetupTestPostgresDB("")
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
		t.Fatalf("error in function: %v", err)
	}

	if token != "token 123" {
		t.Fatal("got invalid token")
	}
}
