package coreplainauth

import (
	"bytes"
	"context"
	"fmt"
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

// logError safely logs error messages if a logger is provided
func (s *Coreplainauth) logError(format string, v ...any) {
	if s.Logger != nil {
		s.Logger.Error(fmt.Sprintf(format, v...))
	}
}

// logWarn safely logs warning messages if a logger is provided
func (s *Coreplainauth) logWarn(format string, v ...any) {
	if s.Logger != nil {
		s.Logger.Warn(fmt.Sprintf(format, v...))
	}
}

// logInfo safely logs info messages if a logger is provided
func (s *Coreplainauth) logInfo(format string, v ...any) {
	if s.Logger != nil {
		s.Logger.Info(fmt.Sprintf(format, v...))
	}
}

// logDebug safely logs debug messages if a logger is provided
func (s *Coreplainauth) logDebug(format string, v ...any) {
	if s.Logger != nil {
		s.Logger.Debug(fmt.Sprintf(format, v...))
	}
}
