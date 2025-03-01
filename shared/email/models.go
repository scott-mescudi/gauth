package email

type EmailProvider interface {
	SendEmail(subject, plainTextContent, htmlContent, toEmail, toName string) error
}

type EmailConfig interface {
	SendEmail(toEmail, toName, link, token string)
}

type TwilioConfig struct {
	FromName  string
	FromEmail string
	ApiKey    string
}
