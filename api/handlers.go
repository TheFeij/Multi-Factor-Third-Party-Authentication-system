package api

import (
	"Third-Party-Multi-Factor-Authentication-System/db"
	"Third-Party-Multi-Factor-Authentication-System/util"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func (s *Server) Signup(context *gin.Context) {
	var req *SignupRequest

	if err := context.ShouldBindJSON(&req); err != nil {
		context.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	user := ConvertSignupRequestToModel(req)
	hashedPassword, err := util.HashPassword(req.Password)
	if err != nil {
		context.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	user.Password = hashedPassword

	err = s.store.InsertUser(user)
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
		Username:     user.Username,
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

	res := SignupResponse{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessTokenPayload.ExpiredAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshTokenPayload.ExpiredAt,
		SessionID:             session.ID,
		UserInformation: UserInformation{
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
			UpdatedAt: time.Time{},
			DeletedAt: time.Time{},
		},
	}
	context.JSON(http.StatusOK, res)
}

func (s *Server) Login(context *gin.Context) {
	var req *LoginRequest

	if err := context.ShouldBindJSON(&req); err != nil {
		context.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	user, err := s.store.GetUserByUsernameAndPassword(req.Username, req.Password)
	if err != nil {
		context.JSON(http.StatusUnauthorized, errorResponse(err))
		return
	}

	//context.HTML(http.StatusOK, "topt.html", nil)
	context.JSON(http.StatusOK, user)
}

func errorResponse(err error) gin.H {
	return gin.H{"message": err.Error()}
}
