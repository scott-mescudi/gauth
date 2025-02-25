package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gAuth/shared/errors"
	v "github.com/scott-mescudi/gAuth/shared/variables"
)

func TestGenerateHMac(t *testing.T) {
	tests := []struct {
		testName      string
		userID        uuid.UUID
		tokenType     int8
		timeFrame     time.Time
		expectToken   bool
		expectedError error
	}{
		{
			testName:      "Valid acess_token generation",
			userID:        uuid.New(),
			tokenType:     v.ACCESS_TOKEN,
			timeFrame:     time.Now().Add(1 * time.Hour),
			expectToken:   true,
			expectedError: nil,
		},
		{
			testName:      "Valid refresh_token generation",
			userID:        uuid.New(),
			tokenType:     v.REFRESH_TOKEN,
			timeFrame:     time.Now().Add(1 * time.Hour),
			expectToken:   true,
			expectedError: nil,
		},
		{
			testName:      "Invalid token type",
			userID:        uuid.New(),
			tokenType:     -112,
			timeFrame:     time.Now().Add(1 * time.Hour),
			expectToken:   false,
			expectedError: errs.ErrInvalidTokenType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			token, err := GenerateHMac(tt.userID, tt.tokenType, tt.timeFrame)

			if !tt.expectToken && token != "" {
				t.Fatal("Got token when not expected")
			}

			if tt.expectedError != err {
				t.Fatalf("expected %v got %v", tt.expectedError, err)
			}
		})
	}
}
