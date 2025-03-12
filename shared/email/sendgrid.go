package email

import (
	"fmt"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

func NewSendGridClient(fromName, fromEmail, apiKey string) *EmailConfig {
	return &EmailConfig{
		FromName:  fromEmail,
		FromEmail: fromEmail,
		ApiKey:    apiKey,
	}
}

func (s *EmailConfig) SendEmail(toEmail, toName, link, token, verifyType, tpl string) error {
	from := mail.NewEmail(s.FromName, s.FromEmail)
	to := mail.NewEmail(toName, toEmail)

	html, err := RenderHtml(fmt.Sprintf("%s/verify/%s?token=%s", link, verifyType, token), tpl)
	if err != nil {
		return err
	}

	message := mail.NewSingleEmail(from, "verify "+verifyType, to, "", html)

	client := sendgrid.NewSendClient(s.ApiKey)
	_, err = client.Send(message)
	return err
}
