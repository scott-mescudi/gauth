package email

import (
	"context"
	"fmt"
	"net/smtp"
	"time"
)

func NewSMTPClient(smtpHost string, smtpPort string, senderEmail string, senderPassword string) *SMTPConfig {
	return &SMTPConfig{
		SMTPhost:       smtpHost,
		SMTPport:       smtpPort,
		SenderEmail:    senderEmail,
		SenderPassword: senderPassword,
		Client:         smtp.PlainAuth("", senderEmail, senderPassword, smtpHost),
	}

}


// will panic if fail to send email
func (s *SMTPConfig) SendEmail(toEmail, toName, domain, token, verifyType, tpl string) error {
	errch := make(chan error, 1)

	html, err := RenderHtml(fmt.Sprintf("%s/verify/%s?token=%s", domain, verifyType, token), tpl)
	if err != nil {
		return err
	}

	subject := "verify " + verifyType
	contentType := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	message := []byte(subject + contentType + html)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancel()

	go func() {
		select {
		case <-ctx.Done():
			errch <- fmt.Errorf("failed to send email: context canceled or timed out")
			return
		default:
			err := smtp.SendMail(s.SMTPhost+":"+s.SMTPport, s.Client, s.SenderEmail, []string{toEmail}, message)
			if err != nil {
				errch <- err
				return
			}

			errch <- nil
		}
	}()

	select {
	case err := <-errch:
		if err != nil {
			panic(fmt.Sprintf("failed to send email: %v", err))
		}
	case <-ctx.Done():
		return fmt.Errorf("failed to send email: Timeout")

	}

	return nil
}
