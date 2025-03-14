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

// SendEmail sends an email to the recipient with the specified verification URL and template
func (s *SMTPConfig) SendEmail(toEmail, toName, verificationURL, tpl string) error {
	html, err := RenderHtml(verificationURL, tpl)
	if err != nil {
		return fmt.Errorf("failed to render HTML: %v", err)
	}

	subject := "Subject: " + "verify " + toName + "\r\n"
	contentType := "MIME-version: 1.0;\r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n"
	fromHeader := "From: " + s.SenderEmail + "\r\n"

	message := []byte(fromHeader + subject + contentType + html)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancel()

	errch := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			errch <- fmt.Errorf("failed to send email: context canceled or timed out")
			return
		default:
			err := smtp.SendMail(s.SMTPhost+":"+s.SMTPport, s.Client, s.SenderEmail, []string{toEmail}, message)
			if err != nil {
				errch <- fmt.Errorf("failed to send email: %v", err)
				return
			}
			errch <- nil
		}
	}()

	select {
	case err := <-errch:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return fmt.Errorf("failed to send email: Timeout")
	}

	return nil
}
