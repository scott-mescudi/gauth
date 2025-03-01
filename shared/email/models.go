package email

type EmailProvider interface {
	SendEmail(subject, plainTextContent, htmlContent, toEmail, toName string) error
}

type TwilioConfig struct {
	FromName  string
	FromEmail string
	ApiKey    string
}
