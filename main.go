package main

import (
	"Third-Party-Multi-Factor-Authentication-System/api"
	"Third-Party-Multi-Factor-Authentication-System/db"
	"Third-Party-Multi-Factor-Authentication-System/tokenmanager/token"
	"log"
)

func main() {
	tokenMaker, err := token.NewPasetoMaker("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		log.Fatal(err)
	}

	store, err := db.NewStore()
	if err != nil {
		log.Fatal(err)
	}

	server := api.NewServer(store, tokenMaker)
	if err != nil {
		log.Fatal(err)
	}

	err = server.StartServer(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
