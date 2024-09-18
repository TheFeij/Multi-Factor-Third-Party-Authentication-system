package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type Server struct {
	router *gin.Engine
}

func NewServer() *Server {
	s := &Server{router: gin.Default()}

	s.setupRouter()

	return s
}

func (s *Server) setupRouter() {
	s.router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"message": "Welcome"})
	})

}

func registerCustomValidators() {
	return
}

func (s *Server) StartServer(address string) error {
	return s.router.Run(address)
}
