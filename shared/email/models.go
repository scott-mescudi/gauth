package email

import "io"

type EmailProvider interface {
	SendEmail(toEmail, toName, domain, token, verifyType, tpl string) error
}

type EmailConfig struct {
	FromName  string
	FromEmail string
	ApiKey    string
}

type MockClient struct {
	Writer io.Writer
}
