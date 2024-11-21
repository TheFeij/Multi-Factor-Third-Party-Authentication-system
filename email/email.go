package email

import (
	"fmt"
	"github.com/jordan-wright/email"
	"net/smtp"
)

const smtpAuthAddress = "smtp.gmail.com"
const smtpServerAddress = "smtp.gmail.com:587"

type EmailSender struct {
	name              string
	fromEmailAddress  string
	fromEmailPassword string
}

func NewEmailSender(name, fromEmailAddress, fromEmailPassword string) *EmailSender {
	return &EmailSender{
		name:              name,
		fromEmailAddress:  fromEmailAddress,
		fromEmailPassword: fromEmailPassword,
	}
}

func (sender *EmailSender) SendEmail(subject, content string, to, cc, bcc, attachFiles []string) error {
	e := email.NewEmail()
	e.From = fmt.Sprintf("%s <%s>", sender.name, sender.fromEmailAddress)
	e.To = to
	e.Bcc = bcc
	e.Cc = cc
	e.Subject = subject
	e.HTML = []byte(content)

	for _, file := range attachFiles {
		_, err := e.AttachFile(file)
		if err != nil {
			return fmt.Errorf("Failed to attach file %s: %w", file, err)
		}
	}

	smtpAuth := smtp.PlainAuth("", sender.fromEmailAddress, sender.fromEmailPassword, smtpAuthAddress)
	err := e.Send(smtpServerAddress, smtpAuth)
	if err != nil {
		return err
	}

	return nil
}
