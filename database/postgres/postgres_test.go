package database

import (
	"context"
	"testing"
	"time"

	_ "github.com/lib/pq"
	tu "github.com/scott-mescudi/gauth/pkg/testutils"
)

func TestAddUserPostgres(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}

	username := "jack"
	email := "jack@gmail.com"
	password := "securepassword123"
	role := "user"

	uuid, err := db.AddUser(t.Context(), "", "", username, email, role, password, true)
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	var isverified bool
	err = conn.QueryRow(t.Context(), "SELECT isverified FROM gauth_user_verification WHERE user_id=$1", uuid).Scan(&isverified)
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	if !isverified {
		t.Error("user is not verified")
	}

	var dbusername, dbemail, dbrole string
	err = conn.QueryRow(t.Context(), "SELECT username, email, role FROM gauth_user WHERE id=$1", uuid).Scan(&dbusername, &dbemail, &dbrole)
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

	db := &PostgresDB{Pool: conn}

	uuid, err := db.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", "password123", true)
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

	db := &PostgresDB{Pool: conn}

	uuid, err := db.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", "password123", true)
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

	db := &PostgresDB{Pool: conn}

	uuid, err := db.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", "password123", true)
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

	db := &PostgresDB{Pool: conn}

	uuid, err := db.AddUser(t.Context(), "", "", "jack", "jack@jack.com", "user", "password123", true)
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

func TestSetUserPassword(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	newPassword := "newpassword123"

	userid, err := db.AddUser(context.Background(), "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	err = db.SetUserPassword(t.Context(), userid, newPassword)
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	var storedHash string
	err = conn.QueryRow(t.Context(), "SELECT password_hash FROM gauth_user_auth WHERE user_id=$1", userid).Scan(&storedHash)
	if err != nil {
		t.Fatal(err)
	}

	if storedHash != newPassword {
		t.Fatal("password hashes don't match")
	}
}

func TestDeleteUser(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}

	userid, err := db.AddUser(context.Background(), "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	err = db.DeleteUser(t.Context(), userid)
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	var exists bool
	err = conn.QueryRow(t.Context(), "SELECT EXISTS (SELECT 1 FROM gauth_user WHERE id=$1)", userid).Scan(&exists)
	if err != nil {
		t.Fatal(err)
	}

	if exists {
		t.Fatal("user was not deleted")
	}
}

func TestGetUserPasswordByID(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	userid, err := db.AddUser(context.Background(), "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	retrievedPassword, err := db.GetUserPasswordByID(t.Context(), userid)
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	if retrievedPassword != "hey" {
		t.Fatal("password hashes don't match")
	}
}

func TestSetUserEmail(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	userid, err := db.AddUser(context.Background(), "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	err = db.SetUserEmail(t.Context(), userid, "jack2@jack.com")
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	var storedEmail string
	err = conn.QueryRow(t.Context(), "SELECT email FROM gauth_user WHERE id=$1", userid).Scan(&storedEmail)
	if err != nil {
		t.Fatal(err)
	}

	if storedEmail != "jack2@jack.com" {
		t.Fatal("emails don't match")
	}
}

func TestGetUserEmail(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	userid, err := db.AddUser(context.Background(), "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	retrievedEmail, err := db.GetUserEmail(t.Context(), userid)
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	if retrievedEmail != "jack@jack.com" {
		t.Fatal("emails don't match")
	}
}

func TestSetIsverified(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	userid, err := db.AddUser(context.Background(), "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	err = db.SetIsverified(t.Context(), userid, true)
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	var isVerified bool
	err = conn.QueryRow(t.Context(), "SELECT isverified FROM gauth_user_verification WHERE user_id=$1", userid).Scan(&isVerified)
	if err != nil {
		t.Fatal(err)
	}

	if !isVerified {
		t.Fatal("isVerified flag not set correctly")
	}
}

func TestSetVerificationTokenAndExpiry(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	userid, err := db.AddUser(context.Background(), "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	token := "verification-token"
	duration := time.Hour

	err = db.SetUserVerificationDetails(t.Context(), userid, "signup", "", token, duration)
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	var storedToken string
	var expiry time.Time
	err = conn.QueryRow(t.Context(), "SELECT verification_token, token_expiry FROM gauth_user_verification WHERE user_id=$1", userid).Scan(&storedToken, &expiry)
	if err != nil {
		t.Fatal(err)
	}

	if storedToken != token {
		t.Fatal("tokens don't match")
	}
}

func TestGetUsername(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	userid, err := db.AddUser(context.Background(), "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	retrievedUsername, err := db.GetUsername(t.Context(), userid)
	if err != nil {
		t.Fatalf("error in function: %v", err)
	}

	if retrievedUsername != "jack" {
		t.Fatal("usernames don't match")
	}
}

func TestFingerprintFunctions(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	ctx := context.Background()

	userid, err := db.AddUser(ctx, "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	fingerprint := "test_fingerprint_value"

	err = db.SetFingerprint(ctx, userid, fingerprint)
	if err != nil {
		t.Fatalf("SetFingerprint failed: %v", err)
	}

	retrievedFingerprint, err := db.GetFingerprint(ctx, userid)
	if err != nil {
		t.Fatalf("GetFingerprint failed: %v", err)
	}

	if retrievedFingerprint != fingerprint {
		t.Fatalf("fingerprints don't match: expected %s, got %s", fingerprint, retrievedFingerprint)
	}
}

func TestSignupMethodFunctions(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	ctx := context.Background()

	userid, err := db.AddUser(ctx, "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	method := "github"
	err = db.SetSignupMethod(ctx, userid, method)
	if err != nil {
		t.Fatalf("SetSignupMethod failed: %v", err)
	}

	retrievedMethod, err := db.GetSignupMethod(ctx, userid)
	if err != nil {
		t.Fatalf("GetSignupMethod failed: %v", err)
	}

	if retrievedMethod != method {
		t.Fatalf("signup methods don't match: expected %s, got %s", method, retrievedMethod)
	}
}

func TestUserImageFunctions(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	ctx := context.Background()

	userid, err := db.AddUser(ctx, "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	testImage := []byte("fake-image-data")
	err = db.SetUserImage(ctx, userid, testImage)
	if err != nil {
		t.Fatalf("SetUserImage failed: %v", err)
	}

	retrievedImage, err := db.GetUserImage(ctx, userid)
	if err != nil {
		t.Fatalf("GetUserImage failed: %v", err)
	}

	if string(retrievedImage) != string(testImage) {
		t.Fatalf("images don't match: expected %s, got %s", string(testImage), string(retrievedImage))
	}
}

func TestGetUserDetails(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	ctx := context.Background()

	userid, err := db.AddUser(ctx, "sdd", "jca", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	username, email, firstName, lastName, signupMethod, role, created, _, err := db.GetUserDetails(ctx, userid)
	if err != nil {
		t.Fatal(err)
	}

	if username != "jack" {
		t.Errorf("Expected username 'jack', got '%s'", username)
	}

	if email != "jack@jack.com" {
		t.Errorf("Expected email 'jack@jack.com', got '%s'", email)
	}

	if firstName != "sdd" {
		t.Errorf("Expected firstName 'jack', got '%s'", firstName)
	}

	if lastName != "jca" {
		t.Errorf("Expected lastName 'jack', got '%s'", lastName)
	}

	if signupMethod != "plain" {
		t.Errorf("Expected signupMethod 'hey', got '%s'", signupMethod)
	}

	if role != "user" {
		t.Errorf("Expected role 'user', got '%s'", role)
	}

	if created.IsZero() {
		t.Errorf("Expected a non-zero created time, got %v", created)
	}
}

func TestGetUserIDByEmail(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	ctx := context.Background()

	userid, err := db.AddUser(ctx, "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	euid, err := db.GetUserIDByEmail(t.Context(), "jack@jack.com")
	if err != nil {
		t.Fatal(err)
	}

	if euid != userid {
		t.Fatal("mismatched user id")
	}
}

func TestUserExists(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	ctx := context.Background()

	userid, err := db.AddUser(ctx, "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	username, err := db.GetUsername(t.Context(), userid)
	if err != nil {
		t.Fatal(err)
	}

	if !db.UserExists(t.Context(), username) {
		t.Fatal("failed to idenitfy if user exists")
	}

	if db.UserExists(t.Context(), "ksdhf") {
		t.Fatal("returned true on non existant user")
	}
}

func TestUserExistsByEmail(t *testing.T) {
	conn, clean, err := tu.SetupTestPostgresDB("")
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	db := &PostgresDB{Pool: conn}
	ctx := context.Background()

	userid, err := db.AddUser(ctx, "", "", "jack", "jack@jack.com", "user", "hey", true)
	if err != nil {
		t.Fatal(err)
	}

	email, err := db.GetUserEmail(t.Context(), userid)
	if err != nil {
		t.Fatal(err)
	}

	if !db.UserExistsByEmail(t.Context(), email) {
		t.Fatal("failed to idenitfy if user exists")
	}

	if db.UserExistsByEmail(t.Context(), "ksdhf") {
		t.Fatal("returned true on non existant user")
	}
}
