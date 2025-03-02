package main

import (
	"net/http"
	"time"
	
)

type poolConfig struct {
	MaxConns        int // required
	MinConns        int // required
	MaxConnLifetime time.Duration // required
	MaxConnIdleTime time.Duration // required
}

type Database struct {
	Driver string // required
	Dsn string // required
	Config *poolConfig // optional
}

type EmailConfig struct {
	FromName string // required
	FromEmail string // required
	ApiKey string // required
	AppDomain string // required
	EmailVerificationRedirectURL string // optional
}

type GauthConfig struct {
	Database *Database // required
	AccessTokenExpiration time.Duration // required
	RefreshTokenExpiration time.Duration // required
	EmailAndPassword bool // required
	EmailConfig *EmailConfig // optional
	Cookie *http.Cookie // optional
}