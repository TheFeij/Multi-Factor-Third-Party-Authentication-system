package main

import (
	"authorization-server/api"
	"authorization-server/config"
	"authorization-server/db"
	"authorization-server/tokenmanager/token"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
)

func main() {
	configs, err := config.LoadConfig("./config", "config.json")
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

	server := api.NewServer(store, tokenMaker, configs)
	if err != nil {
		fmt.Println(err)
	}
	log.Info().Msg(fmt.Sprintf("server started on :8081"))

	log.Info().Msg("starting server...")
	err = server.Start(configs.HTTPServer)
	if err != nil {
		log.Fatal().Err(err).Msg("could not start server")
	}
}
