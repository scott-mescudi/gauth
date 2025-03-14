package email

import (
	"context"
	"fmt"
	"time"

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

func (s *EmailConfig) SendEmail(toEmail, toName, domain, token, verifyType, tpl string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	from := mail.NewEmail(s.FromName, s.FromEmail)
	to := mail.NewEmail(toName, toEmail)

	html, err := RenderHtml(fmt.Sprintf("%s/verify/%s?token=%s", domain, verifyType, token), tpl)
	if err != nil {
		return err
	}

	message := mail.NewSingleEmail(from, "verify "+verifyType, to, "", html)

	client := sendgrid.NewSendClient(s.ApiKey)
	_, err = client.SendWithContext(ctx, message)
	return err
}
