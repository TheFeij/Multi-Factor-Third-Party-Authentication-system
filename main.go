package main

import (
	"Third-Party-Multi-Factor-Authentication-System/api"
	"Third-Party-Multi-Factor-Authentication-System/config"
	"Third-Party-Multi-Factor-Authentication-System/db"
	"Third-Party-Multi-Factor-Authentication-System/email"
	"Third-Party-Multi-Factor-Authentication-System/tokenmanager/token"
	"Third-Party-Multi-Factor-Authentication-System/worker"
	"fmt"
	"github.com/hibiken/asynq"
	"log"
)

func main() {
	configs, err := config.LoadConfig("./config", "config.json")
	if err != nil {
		fmt.Println(err)
	}

	redisOpt := &asynq.RedisClientOpt{
		Addr: configs.RedisAddress,
	}

	taskDistributor := worker.NewRedisTaskDistributor(redisOpt)

	tokenMaker, err := token.NewPasetoMaker(configs.TokenSymmetricKey)
	if err != nil {
		fmt.Println(err)
	}

	store, err := db.NewStore(configs)
	if err != nil {
		fmt.Println(err)
	}

	server := api.NewServer(store, tokenMaker, configs, taskDistributor)
	if err != nil {
		fmt.Println(err)
	}

	emailSender := email.NewEmailSender(configs.EmailSenderName, configs.EmailSenderAddress, configs.EmailSenderPassword)

	go func() {
		err := StartTaskProcessor(redisOpt, store, emailSender)
		if err != nil {
			log.Fatal(err)
		}
	}()

	err = server.StartServer(configs.HTTPServer)
	if err != nil {
		fmt.Println(err)
	}
}

func StartTaskProcessor(opt *asynq.RedisClientOpt, store *db.Store, emailSender *email.EmailSender) error {
	taskProcessor := worker.NewRedisTaskProcessor(opt, store, emailSender)
	err := taskProcessor.Start()
	return err
}
