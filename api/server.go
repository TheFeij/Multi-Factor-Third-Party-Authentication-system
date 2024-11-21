package api

import (
	"Third-Party-Multi-Factor-Authentication-System/config"
	"Third-Party-Multi-Factor-Authentication-System/db"
	"Third-Party-Multi-Factor-Authentication-System/tokenmanager/token"
	"Third-Party-Multi-Factor-Authentication-System/worker"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"log"
	"net/http"
	"net/http/httptest"
)

type Server struct {
	router          *gin.Engine
	store           *db.Store
	tokenMaker      token.Maker
	configs         *config.Config
	taskDistributor *worker.RedisTaskDistributor
}

func NewServer(store *db.Store, tokenMaker token.Maker, configs *config.Config, taskDistributor *worker.RedisTaskDistributor) *Server {
	s := &Server{
		router:          gin.Default(),
		store:           store,
		tokenMaker:      tokenMaker,
		configs:         configs,
		taskDistributor: taskDistributor,
	}

	registerCustomValidators()

	s.setupRouter()

	return s
}

func (s *Server) setupRouter() {
	// Load HTML files
	s.router.LoadHTMLGlob("static/*") // or s.router.LoadHTMLFiles("static/topt.html")

	// CORS middleware configuration
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowMethods = []string{"GET", "POST", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type"}

	// Use the CORS middleware with the custom configuration
	s.router.Use(cors.New(config))

	s.router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"message": "Welcome"})
	})
	s.router.POST("/signup", s.Signup)
	s.router.POST("/login", s.Login)

	// Set up static files using the Static method
	s.router.Static("/home", "./static")

	// Handle requests that don't match any defined routes
	s.router.NoRoute(func(c *gin.Context) {
		c.Redirect(http.StatusPermanentRedirect, "/home")
	})
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
