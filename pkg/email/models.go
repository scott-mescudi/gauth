package email

import (
	"io"
	"net/smtp"
)

type EmailProvider interface {
	SendEmail(toEmail, toName, verificationURL, tpl string) error
}

type SendgridConfig struct {
	FromName  string
	FromEmail string
	ApiKey    string
}

type MockClient struct {
	Writer io.Writer
}

type SMTPConfig struct {
	SMTPhost       string
	SMTPport       string
	SenderEmail    string
	SenderPassword string
	Client         smtp.Auth
}
