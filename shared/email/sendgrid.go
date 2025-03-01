package email

import (
	"fmt"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

// var key = os.Getenv("sendgridkey")

func (s *TwilioConfig) SendEmail(toEmail, toName, link, token string) error {
	from := mail.NewEmail(s.FromName, s.FromEmail)
	to := mail.NewEmail(toName, toEmail)

	html, err := RenderHtml(fmt.Sprintf("%s/verify?token=%s", link, token))
	if err != nil {
		return err
	}

	message := mail.NewSingleEmail(from, "verify email", to, "", html)

	client := sendgrid.NewSendClient(s.ApiKey)
	_, err = client.Send(message)
	return err
}
