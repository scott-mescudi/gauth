package email

import (
	"fmt"
	"regexp"
)

func (s *MockClient) SendEmail(toEmail, toName, verificationURL, tpl string) error {
	re := regexp.MustCompile(`token=([A-Za-z0-9\-_\.]+)`)
	matches := re.FindStringSubmatch(verificationURL)
	if len(matches) < 1 {
		return fmt.Errorf("failed to extreact token from url")
	}

	_, err := s.Writer.Write([]byte(matches[1]))
	return err
}
