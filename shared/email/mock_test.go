package email

import (
	"bytes"
	"testing"
)

func TestSendEmail(t *testing.T) {
	tests := []struct {
		verificationURL string
		expectedToken   string
		expectError     bool
	}{
		{"https://example.com?token=abc123", "abc123", false},
		{"https://example.com?token=1234-5678", "1234-5678", false},
		{"https://example.com?no_token_here", "", true},
	}

	for _, test := range tests {
		t.Run(test.verificationURL, func(t *testing.T) {
			buf := &bytes.Buffer{}
			client := &MockClient{Writer: buf}

			err := client.SendEmail("test@example.com", "Test User", test.verificationURL, "")
			if test.expectError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !test.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !test.expectError && buf.String() != test.expectedToken {
				t.Errorf("expected token %s, got %s", test.expectedToken, buf.String())
			}
		})
	}
}
