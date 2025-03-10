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

func NewEmailProvider(provider string, fromName, fromEmail, apiKey string) EmailProvider {
	switch provider {
	case "sendgrid":
		return NewSendGridClient(fromName, fromEmail, apiKey)
	default:
		return nil
	}
}
