package main

import (
	"identity/common/constants/oauthservices"
	"identity/common/helpers/db"
	"identity/config"
	"identity/models"
)

func main() {
	cfg := config.LoadConfig("./config/.env")
	db := db.Connect(cfg.DSN)
	err := db.AutoMigrate(
		&models.User{},
		&models.Session{},
		&models.OAuth{},
		&models.OAuthService{},
	)
	if err != nil {
		panic(err)
	}

	for _, oauthservice := range oauthservices.OAuthServices {
		err := db.Create(&oauthservice).Error
		if err != nil {
			panic(err)
		}
	}

}
