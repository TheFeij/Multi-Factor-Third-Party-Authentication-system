package api

import (
	"Third-Party-Multi-Factor-Authentication-System/service/db"
	"Third-Party-Multi-Factor-Authentication-System/service/tokenmanager/token"
	"Third-Party-Multi-Factor-Authentication-System/service/util"
	"Third-Party-Multi-Factor-Authentication-System/service/worker"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"time"
)

func (s *Server) Signup(ctx *gin.Context) {
	var req *SignupRequest

	// Bind JSON input to request struct
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	now := time.Now()

	var tempUser *db.TempUser
	// Start a MongoDB session for the transaction
	err := s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		// Step 1: Hash the password
		hashedPassword, err := util.HashPassword(req.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %v", err)
		}

		// Step 2: Create the user model
		tempUser = ConvertSignupRequestToModel(req)
		tempUser.Password = hashedPassword

		tempUser.SecretCode = util.RandomString(6, util.NUMBERS)
		tempUser.ExpiredAt = now.Add(24 * time.Hour)

		// Step 3: Insert the user into the database
		err = s.store.InsertTempUserWithSession(sessCtx, tempUser) // Use the session-aware insert method
		if err != nil {
			return nil, fmt.Errorf("failed to insert user: %v", err)
		}

		// Step 4: Enqueue the task for sending the verification email
		taskPayload := &worker.SendVerificationEmailPayload{ID: tempUser.ID}
		opts := []asynq.Option{
			asynq.MaxRetry(10),
			asynq.ProcessIn(time.Second),
			asynq.Queue(worker.CriticalQueue),
		}
		err = s.taskDistributor.SendVerificationEmail(sessCtx, taskPayload, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to enqueue email task: %v", err)
		}

		return nil, nil
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	// creating tokens
	signupToken, _, err := s.tokenMaker.CreateToken(
		&token.Payload{
			ID:        tempUser.ID,
			Username:  "",
			IssuedAt:  time.Now(),
			ExpiredAt: now.Add(24 * time.Hour),
		},
	)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
	}

	ctx.JSON(http.StatusOK, signupToken)
}

func (s *Server) VerifyEmail(ctx *gin.Context) {
	var req *VerifyEmailRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
	}

	now := time.Now()

	// decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.SignupToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("token expired")))
	}

	// check if temp user is not expired
	tempUser, err := s.store.GetTempUser(payload.ID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
	}
	if tempUser.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("token expired")))
	}

	// check the code
	if tempUser.SecretCode != req.VerificationCode {
		ctx.JSON(http.StatusBadRequest, errorResponse(errors.New("wrong code")))
	}

	// if correct delete the temp user and insert user

	// create private key to generate TOTPs send to the user with tokens
	user := &db.User{
		Username: tempUser.Username,
		Email:    tempUser.Email,
		Password: tempUser.Password,
	}
	err = s.store.InsertUser(user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(errors.New("wrong code")))
	}
}

//func (s *Server) Login(ctx *gin.Context) {
//	var req *LoginRequest
//
//	if err := ctx.ShouldBindJSON(&req); err != nil {
//		ctx.JSON(http.StatusBadRequest, errorResponse(err))
//		return
//	}
//
//	var user *db.User
//	var err error
//	if req.Username != "" {
//		user, err = s.store.GetUserByUsernameAndPassword(req.Username, req.Password)
//	} else {
//		user, err = s.store.GetUserByEmailAndPassword(req.Email, req.Password)
//	}
//	if err != nil {
//		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
//		return
//	}
//
//	if !user.IsEmailVerified {
//		ctx.JSON(http.StatusUnauthorized, errorResponse(fmt.Errorf("email is not verified")))
//		return
//	}
//
//	// creating tokens
//	accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
//		req.Username,
//		time.Minute*15,
//	)
//	if err != nil {
//		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
//	}
//
//	refreshToken, refreshTokenPayload, err := s.tokenMaker.CreateToken(
//		req.Username,
//		time.Minute*60)
//	if err != nil {
//		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
//		return
//	}
//
//	session := &db.Session{
//		ID:           refreshTokenPayload.ID,
//		Username:     user.Username,
//		RefreshToken: refreshToken,
//		UserAgent:    ctx.Request.UserAgent(),
//		ClientIP:     ctx.ClientIP(),
//		IsBlocked:    false,
//		CreatedAt:    time.Now().UTC(),
//		ExpiresAt:    time.Now().UTC(),
//		DeletedAt:    nil,
//	}
//	err = s.store.InsertSession(session)
//	if err != nil {
//		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
//		return
//	}
//
//	res := SignupResponse{
//		AccessToken:           accessToken,
//		AccessTokenExpiresAt:  accessTokenPayload.ExpiredAt,
//		RefreshToken:          refreshToken,
//		RefreshTokenExpiresAt: refreshTokenPayload.ExpiredAt,
//		SessionID:             session.ID,
//		UserInformation: UserInformation{
//			Username:  user.Username,
//			Email:     user.Email,
//			CreatedAt: user.CreatedAt,
//			UpdatedAt: time.Time{},
//			DeletedAt: time.Time{},
//		},
//	}
//
//	ctx.JSON(http.StatusOK, res)
//}

func errorResponse(err error) gin.H {
	return gin.H{"message": err.Error()}
}
