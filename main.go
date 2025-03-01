package main

import (
	"log"
	"net/http"
	"os"
	"time"

	plainauth "github.com/scott-mescudi/gauth/api/plain_auth"
	coreplainauth "github.com/scott-mescudi/gauth/core/plain_auth"
	"github.com/scott-mescudi/gauth/database"
	"github.com/scott-mescudi/gauth/shared/email"
)

func main() {
	conn, err := database.ConnectToDatabase("postgres", "postgresql://admin:admin123@localhost:7323/gauth")
	if err != nil {
		log.Fatalln(err)
	}

	t := plainauth.PlainAuthAPI{
		AuthCore: &coreplainauth.Coreplainauth{
			DB:                     conn,
			AccessTokenExpiration:  1 * time.Hour,
			RefreshTokenExpiration: 24 * time.Hour,
			EmailProvider: &email.TwilioConfig{
				FromName:  "jack",
				FromEmail: os.Getenv("fromEmail"),
				ApiKey:    os.Getenv("sendgridkey"),
			},
			Domain: "http://localhost:8037",
		},
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/signup", t.VerifiedSignup)
	mux.HandleFunc("/verify", t.VerifySignup)
	mux.HandleFunc("/login", t.Login)

	err = http.ListenAndServe(":8037", mux)
	if err != nil {
		log.Fatalln(err)
	}

}
