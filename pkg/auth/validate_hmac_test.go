package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	errs "github.com/scott-mescudi/gauth/pkg/errors"
	v "github.com/scott-mescudi/gauth/pkg/variables"
)

func TestValidateHmac(t *testing.T) {

	s := &JWTConfig{Issuer: "test", Secret: []byte("p87945ihfldjhvlwhib723789")}
	t.Run("Valid token", func(t *testing.T) {
		uuid := uuid.New()
		token, err := s.GenerateHMac(uuid, v.ACCESS_TOKEN, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal("failed to generate token ", err)
		}

		userUuid, tokenType, err := s.ValidateHmac(token)
		if err != nil {
			t.Error("got err when not expected: ", err)
		}

		if tokenType != v.ACCESS_TOKEN {
			t.Error("return token type doesnt match expected")
		}

		if userUuid != uuid {
			t.Error("returned uuid doesnt match expected uuid")
		}
	})

	t.Run("empty token", func(t *testing.T) {
		_, _, err := s.ValidateHmac("")
		if err != errs.ErrEmptyToken {
			t.Errorf("expected %v got %v", errs.ErrEmptyToken, err)
		}
	})

	t.Run("expird token", func(t *testing.T) {
		uuid := uuid.New()
		token, err := s.GenerateHMac(uuid, v.ACCESS_TOKEN, time.Now())
		if err != nil {
			t.Fatal("failed to generate token")
		}

		time.Sleep(1 * time.Second)

		_, _, err = s.ValidateHmac(token)

		if err != errs.ErrInvalidToken {
			t.Errorf("expected %v got %v", errs.ErrInvalidToken, err)
		}
	})

	t.Run("empty user id", func(t *testing.T) {
		token, err := s.GenerateHMac(uuid.Nil, v.ACCESS_TOKEN, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal("failed to generate token")
		}

		_, _, err = s.ValidateHmac(token)

		if err != errs.ErrInvalidUserID {
			t.Errorf("expected %v got %v", errs.ErrInvalidUserID, err)
		}
	})

	t.Run("invalid issuer", func(t *testing.T) {
		uuid := uuid.New()
		token, err := s.GenerateHMac(uuid, v.ACCESS_TOKEN, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal("failed to generate token")
		}

		s.Issuer = ""
		_, _, err = s.ValidateHmac(token)

		if err != errs.ErrInvalidIssuer {
			t.Errorf("expected %v got %v", errs.ErrInvalidIssuer, err)
		}
	})
}
