package helpers

import (
	"identity/common/helpers/apperrors"
	"identity/config"
	"log"

	"gopkg.in/gomail.v2"
)

func SendEmail(cfg *config.Config, to string, data string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", cfg.SMTP_LOGIN)
	m.SetHeader("To", to)
	m.SetHeader("Subject", data)
	d := gomail.NewDialer(cfg.SMTP_SERVER, cfg.SMPT_PORT, cfg.SMTP_USERNAME, cfg.SMTP_PASSWORD)
	err := d.DialAndSend(m)
	if err != nil {
		log.Fatalln("failed send email: ", err)
		err = apperrors.NewInternal("failed send email")
	}
	return err
}
