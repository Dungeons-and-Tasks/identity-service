package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	DSN string

	ALLOW_ORIGINS string

	ADDRESS string

	ACCESS_TOKEN_PRIVATE_KEY_PATH   string
	ACCESS_TOKEN_PUBLIC_KEY_PATH    string
	ACCESS_TOKEN_EXPIRES_IN         time.Duration
	ACCESS_TOKEN_REFRESH_EXPIRES_IN time.Duration
	ACCESS_TOKEN_MAXAGE             time.Duration

	GOOGLE_AUTH_URI      string
	GOOGLE_TOKEN_URI     string
	GOOGLE_USER_INFO_URI string
	GOOGLE_REDIRECT_URI  string
	GOOGLE_CLIENT_SECRET string
	GOOGLE_CLIENT_ID     string
	GOOGLE_SCOPE         []string

	VK_AUTH_URI      string
	VK_TOKEN_URI     string
	VK_USER_INFO_URI string
	VK_API_VERSION   string
	VK_REDIRECT_URI  string
	VK_CLIENT_SECRET string
	VK_CLIENT_ID     string
	VK_SCOPE         []string

	SMTP_SERVER   string
	SMPT_PORT     int
	SMTP_LOGIN    string
	SMTP_USERNAME string
	SMTP_PASSWORD string

	VERIFICATION_CODE_LENGTH     int
	VERIFICATION_CODE_EXPIRES_IN time.Duration

	PASSWORD_RESET_TOKEN_LENGTH     int
	PASSWORD_RESET_TOKEN_EXPIRES_IN time.Duration
}

func LoadConfig(path string) *Config {
	var cfg Config
	viper.SetConfigFile(path)
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
	err = viper.Unmarshal(&cfg)
	if err != nil {
		panic(err)
	}
	return &cfg
}
