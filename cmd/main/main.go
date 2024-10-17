package main

import (
	"Third-Party-Multi-Factor-Authentication-System/api"
	"log"
)

func main() {
	s := api.NewServer()

	err := s.Start(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
