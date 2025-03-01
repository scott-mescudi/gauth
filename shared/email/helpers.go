package email

import (
	"bytes"
	"text/template"
)

func RenderHtml(link string) (string, error) {
	t, err := template.New("webpage").Parse(tpl)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer

	data := struct {
		Link string
	}{
		Link: link,
	}

	err = t.Execute(&buf, data)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func NewSendGridClient(fromName, fromEmail, apiKey string) *TwilioConfig {
	return &TwilioConfig{
		FromName:  fromEmail,
		FromEmail: fromEmail,
		ApiKey:    apiKey,
	}
}
