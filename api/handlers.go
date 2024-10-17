package api

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func (s *Server) Signup(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, "Signup Handler")
}
