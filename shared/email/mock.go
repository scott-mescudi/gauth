package email

func (s *MockClient) SendEmail(toEmail, toName, link, token, verifyType string) error {
	_, err := s.Writer.Write([]byte(token))
	return err
}
