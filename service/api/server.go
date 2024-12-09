package api

import (
	"Third-Party-Multi-Factor-Authentication-System/service/cache"
	"Third-Party-Multi-Factor-Authentication-System/service/config"
	"Third-Party-Multi-Factor-Authentication-System/service/db"
	"Third-Party-Multi-Factor-Authentication-System/service/tokenmanager/token"
	"Third-Party-Multi-Factor-Authentication-System/service/worker"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
	"net/http"
	"net/http/httptest"
	"time"
)

type Server struct {
	router          *gin.Engine
	store           *db.Store
	tokenMaker      *token.PasetoMaker
	configs         *config.Config
	taskDistributor *worker.RedisTaskDistributor
	cache           *cache.Cache
}

func NewServer(store *db.Store, tokenMaker *token.PasetoMaker, configs *config.Config, taskDistributor *worker.RedisTaskDistributor, cache *cache.Cache) *Server {
	s := &Server{
		router:          gin.New(),
		store:           store,
		tokenMaker:      tokenMaker,
		configs:         configs,
		taskDistributor: taskDistributor,
		cache:           cache,
	}

	registerCustomValidators()

	s.setupRouter()

	return s
}

func (s *Server) setupRouter() {
	s.router.Use(gin.Recovery())
	s.router.Use(logMiddleware)

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
	s.router.POST("/verify-email", s.VerifyEmail)
	s.router.POST("/login-approves", s.GetLoginRequests)
	//s.router.POST("/login", s.Login)

	// Handle requests that don't match any defined routes
	s.router.NoRoute(func(c *gin.Context) {
		c.Redirect(http.StatusPermanentRedirect, "/home")
	})
}

func registerCustomValidators() {
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		if err := v.RegisterValidation("validUsername", ValidUsername); err != nil {
			log.Fatal().Msg("could not register validUsername validator")
		}
		if err := v.RegisterValidation("validPassword", ValidPassword); err != nil {
			log.Fatal().Msg("could not register validPassword validator")
		}
		if err := v.RegisterValidation("validFullname", ValidFullname); err != nil {
			log.Fatal().Msg("could not register validFullname validator")
		}
	}
}

func (s *Server) Start(address, cert, key string) error {
	return s.router.RunTLS(address, cert, key)
}

func (s *Server) RouterServeHTTP(recorder *httptest.ResponseRecorder, req *http.Request) {
	s.router.ServeHTTP(recorder, req)
}

var logMiddleware = func(c *gin.Context) {
	start := time.Now()

	// Process request
	c.Next()

	// Log request details
	log.Info().
		Str("method", c.Request.Method).
		Str("path", c.Request.URL.Path).
		Int("status", c.Writer.Status()).
		Dur("duration", time.Since(start)).
		Msg("request handled")
}
