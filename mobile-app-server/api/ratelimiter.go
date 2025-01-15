package api

import (
	ratelimit "github.com/JGLTechnologies/gin-rate-limit"
	"github.com/gin-gonic/gin"
	"strconv"
	"time"
)

func keyFunc(c *gin.Context) string {
	return c.ClientIP()
}

func errorHandler(c *gin.Context, info ratelimit.Info) {
	c.String(429, "تعداد درخواست‌ها بیش از حد مجاز است. بعد از "+strconv.Itoa(int(time.Until(info.ResetTime).Seconds()))+" ثانیه دوباره تلاش کنید.")
}

func NewRateLimiter(rate time.Duration, limit uint) gin.HandlerFunc {
	store := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
		Rate:  rate,
		Limit: limit,
	})
	mw := ratelimit.RateLimiter(store, &ratelimit.Options{
		ErrorHandler: errorHandler,
		KeyFunc:      keyFunc,
	})

	return mw
}
