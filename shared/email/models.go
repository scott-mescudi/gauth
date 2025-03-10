package email

import "io"

type EmailProvider interface {
	SendEmail(toEmail, toName, link, token, verifyType string) error
}

type TwilioConfig struct {
	FromName  string
	FromEmail string
	ApiKey    string
}

type MockClient struct {
	Writer io.Writer
}
