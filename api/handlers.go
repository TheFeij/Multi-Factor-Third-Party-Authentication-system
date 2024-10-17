package api

import (
	"Third-Party-Multi-Factor-Authentication-System/db"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func (s *Server) Signup(context *gin.Context) {
	var req *db.User

	if err := context.ShouldBindJSON(&req); err != nil {
		context.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	err := s.store.InsertUser(req)
	if err != nil {
		context.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
		req.Username,
		time.Minute*15,
	)
	if err != nil {
		context.JSON(http.StatusInternalServerError, errorResponse(err))
	}

	refreshToken, refreshTokenPayload, err := s.tokenMaker.CreateToken(
		req.Username,
		time.Minute*60)
	if err != nil {
		context.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	session := &db.Session{
		ID:           refreshTokenPayload.ID,
		Username:     req.Username,
		RefreshToken: refreshToken,
		UserAgent:    context.Request.UserAgent(),
		ClientIP:     context.ClientIP(),
		IsBlocked:    false,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC(),
		DeletedAt:    nil,
	}
	err = s.store.InsertSession(session)
	if err != nil {
		context.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	res := signupResponse{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessTokenPayload.ExpiredAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenPayload.ExpiredAt,
		SessionID:             session.ID,
		UserInformation: UserInformation{
			Username:  req.Username,
			FullName:  req.Firstname,
			Email:     req.Email,
			CreatedAt: req.CreatedAt,
			UpdatedAt: time.Time{},
			DeletedAt: time.Time{},
		},
	}
	context.JSON(http.StatusOK, res)
}

func errorResponse(err error) gin.H {
	return gin.H{"message": err.Error()}
}
