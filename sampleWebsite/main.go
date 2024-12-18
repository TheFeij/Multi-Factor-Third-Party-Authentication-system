package main

import "github.com/gin-gonic/gin"

func main() {
	router := gin.Default()

	router.GET("/", func(context *gin.Context) {

	})

	router.Run(":4040")
}
