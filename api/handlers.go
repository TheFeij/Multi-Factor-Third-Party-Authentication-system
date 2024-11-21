package api

import (
	"Third-Party-Multi-Factor-Authentication-System/util"
	"Third-Party-Multi-Factor-Authentication-System/worker"
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

	// Start a MongoDB session for the transaction
	session, err := s.store.Client.StartSession()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	defer session.EndSession(ctx)

	// Define the transaction logic
	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		// Step 1: Hash the password
		hashedPassword, err := util.HashPassword(req.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %v", err)
		}

		// Step 2: Create the user model
		user := ConvertSignupRequestToModel(req)
		user.Password = hashedPassword

		// Step 3: Insert the user into the database
		err = s.store.InsertUserWithSession(sessCtx, user) // Use the session-aware insert method
		if err != nil {
			return nil, fmt.Errorf("failed to insert user: %v", err)
		}

		// Step 4: Enqueue the task for sending the verification email
		taskPayload := &worker.SendVerificationEmailPayload{Username: user.Username}
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
	}

	// Run the transaction
	_, err = session.WithTransaction(ctx, callback)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "User created successfully, verification email sent"})
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

	taskPayload := &worker.SendVerificationEmailPayload{Username: user.Username}
	opts := []asynq.Option{
		asynq.MaxRetry(10),
		asynq.ProcessIn(time.Second),
		asynq.Queue(worker.CriticalQueue),
	}

	err = s.taskDistributor.SendVerificationEmail(context, taskPayload, opts...)
	if err != nil {
		context.JSON(http.StatusInternalServerError, errorResponse(err))
	}

	//context.HTML(http.StatusOK, "topt.html", nil)
	context.JSON(http.StatusOK, user)
}

func errorResponse(err error) gin.H {
	return gin.H{"message": err.Error()}
}

/*
accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
		req.Username,
		time.Minute*15,
	)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
	}

	refreshToken, refreshTokenPayload, err := s.tokenMaker.CreateToken(
		req.Username,
		time.Minute*60)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	session := &db.Session{
		ID:           refreshTokenPayload.ID,
		Username:     user.Username,
		RefreshToken: refreshToken,
		UserAgent:    ctx.Request.UserAgent(),
		ClientIP:     ctx.ClientIP(),
		IsBlocked:    false,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC(),
		DeletedAt:    nil,
	}
	err = s.store.InsertSession(session)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
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
*/
