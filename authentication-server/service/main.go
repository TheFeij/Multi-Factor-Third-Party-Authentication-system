package main

import (
	"Third-Party-Multi-Factor-Authentication-System/authentication-server/service/api"
	"Third-Party-Multi-Factor-Authentication-System/authentication-server/service/cache"
	"Third-Party-Multi-Factor-Authentication-System/authentication-server/service/config"
	"Third-Party-Multi-Factor-Authentication-System/authentication-server/service/db"
	"Third-Party-Multi-Factor-Authentication-System/authentication-server/service/email"
	"Third-Party-Multi-Factor-Authentication-System/authentication-server/service/tokenmanager/token"
	"Third-Party-Multi-Factor-Authentication-System/authentication-server/service/worker"
	"fmt"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
)

func main() {
	configs, err := config.LoadConfig("./authentication-server/service/config", "config.json")
	if err != nil {
		panic(fmt.Sprintf("could not load configs: %v", err.Error()))
	}

	if configs.Environment == "development" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	redisOpt := &asynq.RedisClientOpt{
		Addr: configs.RedisAddress,
	}

	taskDistributor := worker.NewRedisTaskDistributor(redisOpt)

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

	cache := cache.GetCache(configs)

	server := api.NewServer(store, tokenMaker, configs, taskDistributor, cache)
	if err != nil {
		fmt.Println(err)
	}
	log.Info().Msg(fmt.Sprintf("server started on %v", configs.HTTPServer))

	emailSender := email.NewEmailSender(configs.EmailSenderName, configs.EmailSenderAddress, configs.EmailSenderPassword)

	go func() {
		log.Info().Msg("starting task processor...")
		err := StartTaskProcessor(redisOpt, store, emailSender)
		if err != nil {
			log.Fatal().Err(err).Msg("could not start task processor")
		}
	}()

	log.Info().Msg("starting server...")
	err = server.Start(configs.HTTPServer, "./service/certificates/server.crt", "./service/certificates/server.key")
	if err != nil {
		log.Fatal().Err(err).Msg("could not start server")
	}
}

func StartTaskProcessor(opt *asynq.RedisClientOpt, store *db.Store, emailSender *email.EmailSender) error {
	taskProcessor := worker.NewRedisTaskProcessor(opt, store, emailSender)
	err := taskProcessor.Start()
	return err
}
