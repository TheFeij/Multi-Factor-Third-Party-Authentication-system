package main

import (
	"Third-Party-Multi-Factor-Authentication-System/api"
	"Third-Party-Multi-Factor-Authentication-System/config"
	"Third-Party-Multi-Factor-Authentication-System/db"
	"Third-Party-Multi-Factor-Authentication-System/tokenmanager/token"
	"fmt"
)

func main() {
	configs, err := config.LoadConfig("./config", "config.json")
	if err != nil {
		fmt.Println(err)
	}

	tokenMaker, err := token.NewPasetoMaker(configs.TokenSymmetricKey)
	if err != nil {
		fmt.Println(err)
	}

	store, err := db.NewStore(configs)
	if err != nil {
		fmt.Println(err)
	}

	server := api.NewServer(store, tokenMaker, configs)
	if err != nil {
		fmt.Println(err)
	}

	err = server.StartServer(configs.HTTPServer)
	if err != nil {
		fmt.Println(err)
	}
}
