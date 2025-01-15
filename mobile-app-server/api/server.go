package api

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"mobile-app-server/cache"
	"mobile-app-server/config"
	"mobile-app-server/db"
	"mobile-app-server/tokenmanager/token"
	"mobile-app-server/worker"
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

	s.setupRouter()

	return s
}

func (s *Server) setupRouter() {
	s.router.Use(gin.Recovery())
	s.router.Use(logMiddleware)

	// CORS middleware configuration
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowMethods = []string{"POST"}
	config.AllowHeaders = []string{"Origin", "Content-Type"}
	s.router.Use(cors.New(config))

	s.router.POST("api/signup", NewRateLimiter(30*time.Second, 1), s.Signup)
	s.router.POST("api/verify-email", NewRateLimiter(30*time.Second, 3), s.VerifyEmail)
	s.router.POST("api/login-approves", s.GetLoginRequests)
	s.router.POST("api/android-login", NewRateLimiter(15*time.Minute, 3), s.AndroidAppLogin)
	s.router.POST("api/verify-android-login", NewRateLimiter(15*time.Minute, 5), s.VerifyAndroidAppLogin)
	s.router.POST("api/approve-login", NewRateLimiter(15*time.Minute, 5), s.ApproveLoginRequests)
	s.router.POST("api/refresh-token", NewRateLimiter(15*time.Minute, 2), s.RefreshToken)
	s.router.POST("api/get-approve-logs", NewRateLimiter(1*time.Minute, 3), s.GetApproveLogs)
}

func (s *Server) Start(address, cert, key string) error {
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
