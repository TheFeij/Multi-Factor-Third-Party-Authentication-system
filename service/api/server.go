package api

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
	s.router.POST("api/signup", s.Signup)
	s.router.POST("api/verify-email", s.VerifyEmail)
	s.router.POST("api/login-approves", s.GetLoginRequests)
	s.router.POST("api/android-login", s.AndroidAppLogin)
	s.router.POST("api/verify-android-login", s.VerifyAndroidAppLogin)
	s.router.POST("api/login", s.Login)
	s.router.POST("api/totp-approve", s.VerifyLoginWithTOTP)
	s.router.GET("api/notif-approve", s.VerifyLoginWithAndroidAppNotification)
	s.router.POST("api/approve-login", s.ApproveLoginRequests)
	s.router.POST("api/refresh-token", s.RefreshToken)

	//// Handle requests that don't match any defined routes
	//s.router.NoRoute(func(c *gin.Context) {
	//	c.Redirect(http.StatusPermanentRedirect, "/home")
	//})
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
