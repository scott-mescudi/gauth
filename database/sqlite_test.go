package database

import (
	tu "github.com/scott-mescudi/gauth/shared/testutils"
	"testing"
)

func TestAddUserSqlite(t *testing.T) {
	conn, clean, err := tu.SetupTestSqliteDB("")
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
		t.Fatalf("error in function: %v", err)
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
	conn, clean, err := tu.SetupTestSqliteDB("")
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
	conn, clean, err := tu.SetupTestSqliteDB("")
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
	conn, clean, err := tu.SetupTestSqliteDB("")
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
	conn, clean, err := tu.SetupTestSqliteDB("")
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
