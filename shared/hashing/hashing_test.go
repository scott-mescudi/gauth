package hashing

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "securepassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	if !strings.Contains(hash, "$argon2id$") {
		t.Errorf("Hash does not contain expected format: %s", hash)
	}
}

func TestComparePassword(t *testing.T) {
	password := "securepassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	match, err := ComparePassword(password, hash)
	if err != nil {
		t.Fatalf("ComparePassword returned an error: %v", err)
	}

	if !match {
		t.Errorf("ComparePassword did not return a match for the correct password")
	}
}

func TestCheckHashInvalidHash(t *testing.T) {
	password := "securepassword"
	invalidHash := "$argon2id$v=19$m=65536,t=3,p=4$invalidsalt$invalidkey"

	match, err := ComparePassword(password, invalidHash)
	if err == nil {
		t.Errorf("CheckHash did not return an error for an invalid hash")
	}

	if match {
		t.Errorf("CheckHash incorrectly returned a match for an invalid hash")
	}
}

func TestDecodeHash(t *testing.T) {
	password := "securepassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	params, salt, key, err := DecodeHash(hash)
	if err != nil {
		t.Fatalf("DecodeHash returned an error: %v", err)
	}

	if params == nil || len(salt) == 0 || len(key) == 0 {
		t.Errorf("DecodeHash returned empty values")
	}
}

func TestRoundeTrip(t *testing.T) {
	password := "hey"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword returned an error: %v", err)
	}

	match, err := ComparePassword(password, hash)
	if err != nil || !match {
		t.Fatalf("CheckHash returned an error: %v", err)
	}

}
