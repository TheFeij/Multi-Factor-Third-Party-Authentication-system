package api

import (
	"admin-server/db"
	"admin-server/tokenmanager/token"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) GetUsers(ctx *gin.Context) {
	pageStr := ctx.DefaultQuery("page", "1")
	pageSizeStr := ctx.DefaultQuery("pageSize", "10")

	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil {
		return
	}

	// Fetch the users with pagination
	users, err := s.store.GetUsers(int64(page), int64(pageSize))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	// Respond with the list of users
	ctx.JSON(http.StatusOK, users)
}

func (s *Server) Update(ctx *gin.Context) {
	var user *db.User
	if err := ctx.ShouldBindJSON(&user); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	user, err := s.store.UpdateUser(user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, user)
}

func (s *Server) Delete(ctx *gin.Context) {
	id := ctx.Param("id")
	userID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	err = s.store.DeleteUser(userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.Status(http.StatusOK)
}

func (s *Server) Login(ctx *gin.Context) {
	var req *LoginReq

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	var admin db.Admin
	admin, err := s.store.GetAdminByUsernameAndPassword(req.Username, req.Password)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
		return
	}

	var loginToken string
	loginToken, _, err = s.tokenMaker.CreateToken(
		&token.Payload{
			ID:        admin.ID,
			Username:  "",
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(8 * time.Hour),
		},
	)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, &LoginResp{LoginToken: loginToken})
}
