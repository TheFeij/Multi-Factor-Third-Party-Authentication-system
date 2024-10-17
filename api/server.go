package api

import (
	"Third-Party-Multi-Factor-Authentication-System/db"
	"Third-Party-Multi-Factor-Authentication-System/tokenmanager/token"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"log"
	"net/http"
	"net/http/httptest"
)

type Server struct {
	router     *gin.Engine
	store      *db.Store
	tokenMaker token.Maker
}

func NewServer(store *db.Store, tokenMaker token.Maker) *Server {
	s := &Server{
		router:     gin.Default(),
		store:      store,
		tokenMaker: tokenMaker,
	}

	registerCustomValidators()

	s.setupRouter()

	return s
}

func (s *Server) setupRouter() {
	s.router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"message": "Welcome"})
	})
	s.router.POST("/signup", s.Signup)
}

func (s *Server) StartServer(address string) error {
	return s.router.Run(address)
}

func registerCustomValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		if err := v.RegisterValidation("validUsername", ValidUsername); err != nil {
			log.Fatal("could not register validUsername validator")
		}
		if err := v.RegisterValidation("validPassword", ValidPassword); err != nil {
			log.Fatal("could not register validPassword validator")
		}
		if err := v.RegisterValidation("validFullname", ValidFullname); err != nil {
			log.Fatal("could not register validFullname validator")
		}
	}
}

func (s *Server) Start(address string) error {
	return s.router.Run(address)
}

func (s *Server) RouterServeHTTP(recorder *httptest.ResponseRecorder, req *http.Request) {
	s.router.ServeHTTP(recorder, req)
}
