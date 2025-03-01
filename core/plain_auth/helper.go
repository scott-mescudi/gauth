package coreplainauth

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/rand"
)

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func ComparePassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandomString(length int) (string, error) {
	charsetLen := len(charset)

	b := strings.Builder{}

	for i := 0; i < length; i++ {
		idx := rand.Intn(charsetLen)
		b.WriteByte(charset[idx])

	}

	return b.String(), nil
}
