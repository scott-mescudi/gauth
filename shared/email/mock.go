package email

import "io"

type MockClient struct {
	writer io.Writer
}

func (s *MockClient) SendEmail(toEmail, toName, link, token, verifyType string) error {
	_, err := s.writer.Write([]byte(token))
	return err
}