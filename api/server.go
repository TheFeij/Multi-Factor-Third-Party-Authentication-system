package api

import (
	"Third-Party-Multi-Factor-Authentication-System/config"
	"Third-Party-Multi-Factor-Authentication-System/db"
	"Third-Party-Multi-Factor-Authentication-System/tokenmanager/token"
	"github.com/gin-contrib/cors"
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
	configs    *config.Config
}

func NewServer(store *db.Store, tokenMaker token.Maker, configs *config.Config) *Server {
	s := &Server{
		router:     gin.Default(),
		store:      store,
		tokenMaker: tokenMaker,
		configs:    configs,
	}

	registerCustomValidators()

	s.setupRouter()

	return s
}

func (s *Server) setupRouter() {
	// CORS middleware configuration
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:63342"} // Update this with your frontend's origin
	config.AllowMethods = []string{"GET", "POST", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type"}
	config.AllowCredentials = true // Allow credentials if needed (e.g., cookies)

	// Use the CORS middleware with the custom configuration
	s.router.Use(cors.New(config))

	s.router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"message": "Welcome"})
	})
	s.router.POST("/signup", s.Signup)
	s.router.POST("/login", s.Login)
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
