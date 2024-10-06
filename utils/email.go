package utils

import "net/smtp"

const (
	from     = "testmail@testmail.com"
	password = "testpassword"
	smtpHost = "smtp.gmail.com"
	smtpPort = "777"
)

func SendEmail(to, subject, body string) error {
	msg := []byte("To: " + to + "\n" + "Subject: " + subject + "\n" + "\n" + body)
	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, msg)

	if err != nil {
		return err
	}

	return nil
}
