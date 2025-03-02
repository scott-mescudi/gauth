package coreplainauth

import (
	"bytes"
	"net/http"
	"strings"

	"math/rand/v2"

	jsoniter "github.com/json-iterator/go"
	"golang.org/x/crypto/bcrypt"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

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

	for range length {
		idx := rand.IntN(charsetLen)
		b.WriteByte(charset[idx])

	}

	return b.String(), nil
}

type WebhookRequest struct {
	Message string `json:"message"`
}

func InvokeWebhook(method, callbackURL, authHeader, authHeaderValue, message string) error {
	body, err := json.Marshal(WebhookRequest{Message: message})
	if err != nil {
		return err
	} 

	req, err := http.NewRequest(method, callbackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}

	client := &http.Client{}

	_, err = client.Do(req)
	if err != nil {
		return err
	}

	return nil
}