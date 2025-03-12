package coreplainauth

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"

	"math/rand/v2"

	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

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

func (s *WebhookConfig) InvokeWebhook(ctx context.Context, identifier, message string) error {
	ctx, cancel := context.WithTimeout(ctx, 1000*time.Millisecond)
	defer cancel()

	body, err := json.Marshal(WebhookRequest{Identifier: identifier, Message: message})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, s.Method, s.CallbackURL, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(s.AuthHeader, s.AuthHeaderValue)

	client := &http.Client{}

	_, err = client.Do(req)
	if err != nil {
		return err
	}

	return nil
}
