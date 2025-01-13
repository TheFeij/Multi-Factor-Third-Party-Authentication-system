package api

import (
	"admin-server/config"
	"admin-server/db"
	"admin-server/tokenmanager/token"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"net/http"
	"net/http/httptest"
	"time"
)

type Server struct {
	router     *gin.Engine
	store      *db.Store
	tokenMaker *token.PasetoMaker
	configs    *config.Config
}

func NewServer(store *db.Store, tokenMaker *token.PasetoMaker, configs *config.Config) *Server {
	s := &Server{
		router:     gin.New(),
		store:      store,
		tokenMaker: tokenMaker,
		configs:    configs,
	}

	s.setupRouter()

	return s
}

func (s *Server) setupRouter() {
	s.router.Use(gin.Recovery())
	s.router.Use(logMiddleware)

	// CORS middleware configuration
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowMethods = []string{"GET", "POST", "OPTIONS", "DELETE", "PUT"}
	config.AllowHeaders = []string{"Origin", "Content-Type"}
	s.router.Use(cors.New(config))

	// OAuth endpoints
	s.router.POST("/login", s.Login)
	s.router.GET("/users", authMiddleWare(s.tokenMaker), s.GetUsers)
	s.router.PUT("/users", authMiddleWare(s.tokenMaker), s.Update)
	s.router.DELETE("/users/:id", authMiddleWare(s.tokenMaker), s.Delete)
}

func (s *Server) Start(address string) error {
	return s.router.Run(address)
}

func (s *Server) RouterServeHTTP(recorder *httptest.ResponseRecorder, req *http.Request) {
	s.router.ServeHTTP(recorder, req)
}

func errorResponse(err error) gin.H {
	return gin.H{"message": err.Error()}
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
