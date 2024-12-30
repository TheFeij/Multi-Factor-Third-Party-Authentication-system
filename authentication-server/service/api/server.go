package api

import (
	"authentication-server/service/cache"
	"authentication-server/service/config"
	"authentication-server/service/db"
	"authentication-server/service/tokenmanager/token"
	"authentication-server/service/worker"
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
	config.AllowMethods = []string{"GET", "POST", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type"}
	s.router.Use(cors.New(config))

	// Serve static files
	s.router.Static("/static", "./front/static")

	// Set the directory for HTML templates
	s.router.LoadHTMLGlob("./front/templates/*.html")

	s.router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "loginpage.html", nil)
	})

	s.router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{"message": "Welcome"})
	})
	s.router.POST("api/signup", NewRateLimiter(30*time.Second, 1), s.Signup)
	s.router.POST("api/verify-email", NewRateLimiter(30*time.Second, 3), s.VerifyEmail)
	s.router.POST("api/login-approves", s.GetLoginRequests)
	s.router.POST("api/android-login", NewRateLimiter(15*time.Minute, 3), s.AndroidAppLogin)
	s.router.POST("api/verify-android-login", NewRateLimiter(15*time.Minute, 5), s.VerifyAndroidAppLogin)
	s.router.POST("api/login", NewRateLimiter(30*time.Second, 1), s.Login)
	s.router.POST("api/totp-approve", NewRateLimiter(15*time.Minute, 5), s.VerifyLoginWithTOTP)
	s.router.GET("api/notif-approve", NewRateLimiter(15*time.Minute, 2), s.VerifyLoginWithAndroidAppNotification)
	s.router.POST("api/approve-login", NewRateLimiter(15*time.Minute, 5), s.ApproveLoginRequests)
	s.router.POST("api/refresh-token", NewRateLimiter(15*time.Minute, 2), s.RefreshToken)

	//// Handle requests that don't match any defined routes
	//s.router.NoRoute(func(c *gin.Context) {
	//	c.Redirect(http.StatusPermanentRedirect, "/home")
	//})
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
