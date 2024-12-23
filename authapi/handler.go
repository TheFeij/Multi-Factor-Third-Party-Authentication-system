package authapi

import (
	"Third-Party-Multi-Factor-Authentication-System/service/tokenmanager/token"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

// Token Exchange
func (s *Server) Token(ctx *gin.Context) {
	var req struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	//// Validate the request
	//if req.GrantType != "authorization_code" || req.Code == "" {
	//	ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid grant type or missing code"})
	//	return
	//}

	// Verify the authorization code (replace this with your token verification logic)
	payload, err := s.tokenMaker.VerifyToken(req.Code)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired authorization code"})
		return
	}

	// Generate an access token
	accessToken, _, err := s.tokenMaker.CreateToken(&token.Payload{
		ID:        payload.ID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
		"expires_in":   3600,
	})
}

// User Info Endpoint
func (s *Server) UserInfo(ctx *gin.Context) {
	var req *struct {
		AccessToken string `json:"access_token,omitempty"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Verify the access token
	payload, err := s.tokenMaker.VerifyToken(req.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired access token"})
		return
	}

	// Fetch user details from the database
	user, err := s.store.GetUser(payload.ID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user details"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
	})
}
