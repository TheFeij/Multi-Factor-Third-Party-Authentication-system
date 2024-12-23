package authapi

import (
	"Third-Party-Multi-Factor-Authentication-System/service/cache"
	"Third-Party-Multi-Factor-Authentication-System/service/config"
	"Third-Party-Multi-Factor-Authentication-System/service/db"
	"Third-Party-Multi-Factor-Authentication-System/service/tokenmanager/token"
	"Third-Party-Multi-Factor-Authentication-System/service/worker"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
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
	config.AllowMethods = []string{"GET", "POST", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type"}
	s.router.Use(cors.New(config))

	// OAuth endpoints
	s.router.POST("/oauth/token", s.Token)
	s.router.GET("/userinfo", s.UserInfo)
}

func (s *Server) Start(address string) error {
	return s.router.Run(address)
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
