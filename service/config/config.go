package config

import (
	"github.com/spf13/viper"
	"time"
)

type Config struct {
	Environment               string        `mapstrucutre:"ENVIRONMENT"`
	DatabaseSource            string        `mapstructure:"DATABASE_SOURCE"`
	DatabaseName              string        `mapstructure:"DATABASE_NAME"`
	HTTPServer                string        `mapstructure:"HTTP_SERVER"`
	TokenSymmetricKey         string        `mapstructure:"TOKEN_SYMMETRIC_KEY"`
	TokenAccessTokenDuration  time.Duration `mapstructure:"TOKEN_ACCESS_TOKEN_DURATION"`
	TokenRefreshTokenDuration time.Duration `mapstructure:"TOKEN_REFRESH_TOKEN_DURATION"`
	RedisAddress              string        `mapstructure:"REDIS_ADDRESS"`
	EmailSenderName           string        `mapstructure:"EMAIL_SENDER_NAME"`
	EmailSenderAddress        string        `mapstructure:"EMAIL_SENDER_ADDRESS"`
	EmailSenderPassword       string        `mapstructure:"EMAIL_SENDER_PASSWORD"`
	EncryptionKey             string        `mapstructure:"ENCRYPTION_KEY"`
}

func LoadConfig(path, name string) (*Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName(name)
	viper.SetConfigType("json")

	viper.AutomaticEnv()

	var config *Config
	if err := viper.ReadInConfig(); err != nil {
		return config, err
	}

	if err := viper.Unmarshal(&config); err != nil {
		return config, err
	}

	return config, nil
}
