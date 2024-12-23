package main

import (
	"Third-Party-Multi-Factor-Authentication-System/authapi"
	"Third-Party-Multi-Factor-Authentication-System/service/config"
	"Third-Party-Multi-Factor-Authentication-System/service/db"
	"Third-Party-Multi-Factor-Authentication-System/service/email"
	"Third-Party-Multi-Factor-Authentication-System/service/tokenmanager/token"
	worker2 "Third-Party-Multi-Factor-Authentication-System/service/worker"
	"fmt"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
)

func main() {
	configs, err := config.LoadConfig("./service/config", "config.json")
	if err != nil {
		panic(fmt.Sprintf("could not load configs: %v", err.Error()))
	}

	if configs.Environment == "development" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	tokenMaker, err := token.NewPasetoMaker(configs.TokenSymmetricKey)
	if err != nil {
		log.Fatal().Err(err).Msg("could not create paseto maker instance")
	}
	log.Info().Msg("token maker instance was created")

	store, err := db.NewStore(configs)
	if err != nil {
		log.Fatal().Err(err).Msg("could not initialize database")
	}
	log.Info().Msg("initialized database")

	server := authapi.NewServer(store, tokenMaker, configs)
	if err != nil {
		fmt.Println(err)
	}
	log.Info().Msg(fmt.Sprintf("server started on :4040"))

	log.Info().Msg("starting server...")
	err = server.Start(":8081")
	if err != nil {
		log.Fatal().Err(err).Msg("could not start server")
	}
}

func StartTaskProcessor(opt *asynq.RedisClientOpt, store *db.Store, emailSender *email.EmailSender) error {
	taskProcessor := worker2.NewRedisTaskProcessor(opt, store, emailSender)
	err := taskProcessor.Start()
	return err
}
