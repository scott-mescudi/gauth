package email

import (
	"context"
	"time"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

func NewSendGridClient(fromName, fromEmail, apiKey string) *SendgridConfig {
	return &SendgridConfig{
		FromName:  fromEmail,
		FromEmail: fromEmail,
		ApiKey:    apiKey,
	}
}

// %s/verify/%s?token=%s", domain, verifyType, token
func (s *SendgridConfig) SendEmail(toEmail, toName, verificationURL, tpl string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	from := mail.NewEmail(s.FromName, s.FromEmail)
	to := mail.NewEmail(toName, toEmail)

	html, err := RenderHtml(verificationURL, tpl)
	if err != nil {
		return err
	}

	message := mail.NewSingleEmail(from, "Verification Email", to, "", html)

	client := sendgrid.NewSendClient(s.ApiKey)
	_, err = client.SendWithContext(ctx, message)
	return err
}
