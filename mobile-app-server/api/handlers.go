package api

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"math/rand"
	"mobile-app-server/db"
	"mobile-app-server/tokenmanager/token"
	"mobile-app-server/util"
	"mobile-app-server/worker"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) Signup(ctx *gin.Context) {
	var req *SignupRequest

	// Bind JSON input to request struct
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("unmarshalling request failed")
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	if err := ValidateOnSignup(s.store, req); err != nil {
		log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("input validations failed")
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	var tempUser *db.TempUser
	// Start a MongoDB session for the transaction
	err := s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		// Step 1: Hash the password
		hashedPassword, err := util.HashPassword(req.Password)
		if err != nil {
			log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("hashing password failed")
			return nil, ErrInternalServer
		}

		// Step 2: Create the user model
		tempUser = ConvertSignupRequestToModel(req)
		tempUser.Password = hashedPassword
		tempUser.SecretCode = util.RandomString(6, util.NUMBERS)
		tempUser.ExpiredAt = time.Now().Add(24 * time.Hour)

		// Step 3: Insert the user into the database
		err = s.store.InsertTempUserWithSession(sessCtx, tempUser) // Use the session-aware insert method
		if err != nil {
			log.Error().Err(err)
			return nil, ErrInternalServer
		}
		log.Info().Str("req", fmt.Sprintf("%+v", req)).Str("temp-user", fmt.Sprintf("%v", tempUser)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("temp user inserted")

		// Step 4: Enqueue the task for sending the verification email
		taskPayload := &worker.SendVerificationEmailPayload{ID: tempUser.ID}
		opts := []asynq.Option{
			asynq.MaxRetry(10),
			asynq.ProcessIn(time.Second),
			asynq.Queue(worker.CriticalQueue),
		}
		err = s.taskDistributor.SendVerificationEmail(sessCtx, taskPayload, opts...)
		if err != nil {
			log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("hashing password failed")
			return nil, ErrInternalServer
		}

		log.Info().Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("signup verification email sent")

		return nil, nil
	})
	if err != nil {
		log.Error().Err(err).Str("req", fmt.Sprintf("%v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("transaction failed")
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	signupToken, _, err := s.tokenMaker.CreateToken(
		&token.Payload{
			ID:        tempUser.ID,
			Username:  "",
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(24 * time.Hour),
		},
	)
	if err != nil {
		log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("signup token creation failed")
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}
	log.Info().Str("req", fmt.Sprintf("%+v", req)).Str("token", signupToken).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("signup token created")

	reqLog := db.Log{
		Type:       db.AndroidAppSignupFirstStep,
		Username:   req.Username,
		Token:      signupToken,
		DeviceInfo: ctx.Request.Header.Get("User-Agent"),
		IP:         ctx.ClientIP(),
		CreatedAt:  time.Now(),
	}
	err = s.store.InsertLog(&reqLog)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	ctx.JSON(http.StatusOK, &SignupResponse{SignupToken: signupToken})
}

func (s *Server) VerifyEmail(ctx *gin.Context) {
	var req *VerifyEmailRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("unmarshalling request failed")
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	// Decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.SignupToken)
	if err != nil {
		log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("signup token verification failed")
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}

	var user *db.User
	var resp *AuthVerificationResponse

	err = s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		// Check if temp user is not expired
		tempUser, err := s.store.GetTempUserWithSession(sessCtx, payload.ID)
		if err != nil {
			log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to fetch temp user")
			return nil, err
		}

		if tempUser.ExpiredAt.Before(time.Now()) {
			log.Error().Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("temp user expired")
			return nil, ErrExpiredSignupToken
		}

		// Check the code
		if tempUser.SecretCode != req.VerificationCode {
			log.Error().Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("invalid verification code")

			reqLog := db.Log{
				Type:          db.AndroidAppSignupSecondStep,
				Username:      tempUser.Username,
				DeviceInfo:    ctx.Request.Header.Get("User-Agent"),
				IP:            ctx.ClientIP(),
				Approved:      false,
				ApproveMethod: db.Email,
				CreatedAt:     time.Now(),
			}
			err = s.store.InsertLog(&reqLog)
			if err != nil {
				return nil, ErrInvalidTOTP
			}

			return nil, ErrInvalidTOTP
		}

		// If correct, delete the temp user and insert user
		err = s.store.DeleteTempUserWithSession(sessCtx, tempUser.ID)
		if err != nil {
			log.Error().Str("req", fmt.Sprintf("%+v", req)).Err(err).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to delete temp user")
			return nil, ErrInternalServer
		}

		// Create key for TOTP generation
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "MFA",
			AccountName: tempUser.Username,
		})
		if err != nil {
			log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to generate TOTP key")
			return nil, ErrInternalServer
		}

		cipherKey, err := util.Encrypt(key.Secret(), s.configs.EncryptionKey)
		if err != nil {
			log.Error().Err(err).Str("secret", key.Secret()).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to encrypt TOTP secret")
			return nil, ErrInternalServer
		}

		// Create private key to generate TOTPs and send to the user with tokens
		user = &db.User{
			Username:   tempUser.Username,
			Email:      tempUser.Email,
			Password:   tempUser.Password,
			TOTPSecret: cipherKey,
		}

		err = s.store.InsertUserWithSession(sessCtx, user)
		if err != nil {
			log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("user", fmt.Sprintf("%+v", user)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to insert user")
			return nil, ErrInternalServer
		}

		// Create tokens
		refreshToken, refreshTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: time.Now().Add(30 * 24 * time.Hour),
			})
		if err != nil {
			log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to create refresh token")
			return nil, ErrInternalServer
		}

		accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: time.Now().Add(15 * time.Minute),
			})
		if err != nil {
			log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to create access token")
			return nil, ErrInternalServer
		}

		resp = &AuthVerificationResponse{
			AccessToken:           accessToken,
			AccessTokenExpiresAt:  accessTokenPayload.ExpiredAt,
			RefreshToken:          refreshToken,
			RefreshTokenExpiresAt: refreshTokenPayload.ExpiredAt,
			UserInformation: UserInformation{
				Username:  user.Username,
				Email:     user.Email,
				CreatedAt: user.CreatedAt,
				UpdatedAt: user.UpdatedAt,
				DeletedAt: time.Time{},
			},
			TOTPSecret: key.Secret(),
		}

		reqLog := db.Log{
			Type:          db.AndroidAppSignupSecondStep,
			Token:         refreshToken,
			Username:      tempUser.Username,
			DeviceInfo:    ctx.Request.Header.Get("User-Agent"),
			IP:            ctx.ClientIP(),
			Approved:      true,
			ApproveMethod: db.Email,
			CreatedAt:     time.Now(),
		}
		err = s.store.InsertLog(&reqLog)
		if err != nil {
			return nil, ErrInternalServer
		}

		return nil, nil
	})
	if err != nil {
		log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("transaction failed")
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func (s *Server) AndroidAppLogin(ctx *gin.Context) {
	var req *LoginRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	if err := ValidateOnAndroidAppLogin(s.store, req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	var tempUser *db.TempUser
	// Start a MongoDB session for the transaction
	err := s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		var user *db.User
		var err error

		if req.Username != "" {
			user, err = s.store.GetUserByUsernameAndPassword(req.Username, req.Password)
		} else {
			user, err = s.store.GetUserByEmailAndPassword(req.Email, req.Password)
		}
		if err != nil {
			return nil, ErrInvalidCredentials
		}

		// Step 2: Create the user model
		tempUser = &db.TempUser{
			Username:   user.Username,
			Email:      user.Email,
			Password:   user.Password,
			ExpiredAt:  time.Now().Add(time.Minute * 10),
			SecretCode: util.RandomString(6, util.NUMBERS),
		}

		// Step 3: Insert the user into the database
		err = s.store.InsertTempUserWithSession(sessCtx, tempUser) // Use the session-aware insert method
		if err != nil {
			return nil, ErrInternalServer
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
			return nil, ErrInternalServer
		}

		return nil, nil
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	// creating tokens
	loginToken, _, err := s.tokenMaker.CreateToken(
		&token.Payload{
			ID:        tempUser.ID,
			Username:  "",
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(10 * time.Minute),
		},
	)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	reqLog := db.Log{
		Type:       db.AndroidAppLoginFirstStep,
		Username:   tempUser.Username,
		Token:      loginToken,
		DeviceInfo: ctx.Request.Header.Get("User-Agent"),
		IP:         ctx.ClientIP(),
		CreatedAt:  time.Now(),
	}
	err = s.store.InsertLog(&reqLog)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	ctx.JSON(http.StatusOK, &AndroidLoginResponse{LoginToken: loginToken})
}

func (s *Server) VerifyAndroidAppLogin(ctx *gin.Context) {
	var req *VerifyAndroidLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
	}

	now := time.Now()

	// decode the login token
	payload, err := s.tokenMaker.VerifyToken(req.LoginToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}

	var user *db.User
	var resp *AuthVerificationResponse

	err = s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		// check if temp user is not expired
		tempUser, err := s.store.GetTempUserWithSession(sessCtx, payload.ID)
		if err != nil {
			return nil, err
		}
		if tempUser.ExpiredAt.Before(now) {
			return nil, ErrTokenExpired
		}

		// check the code
		if tempUser.SecretCode != req.VerificationCode {
			reqLog := db.Log{
				Type:          db.AndroidAppLoginSecondStep,
				Username:      user.Username,
				Token:         "",
				DeviceInfo:    ctx.Request.Header.Get("User-Agent"),
				IP:            ctx.ClientIP(),
				Approved:      false,
				ApproveMethod: db.Email,
				CreatedAt:     time.Now(),
			}
			err = s.store.InsertLog(&reqLog)
			if err != nil {
				return nil, ErrInvalidTOTP
			}

			return nil, ErrInvalidTOTP
		}

		user, err = s.store.GetUserByUsername(tempUser.Username)
		if err != nil {
			return nil, ErrUsernameEmailNotFound
		}

		// if correct delete the temp user and insert user
		err = s.store.DeleteTempUserWithSession(sessCtx, tempUser.ID)
		if err != nil {
			return nil, ErrUserNotFound
		}

		totpSecret, err := util.Decrypt(user.TOTPSecret, s.configs.EncryptionKey)
		if err != nil {
			return nil, ErrInternalServer
		}

		// creating tokens
		refreshToken, refreshTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: now.Add(30 * 24 * time.Hour),
			})
		if err != nil {
			return nil, ErrInternalServer
		}

		accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: now.Add(15 * time.Minute),
			})
		if err != nil {
			return nil, ErrInternalServer
		}

		reqLog := db.Log{
			Type:          db.AndroidAppLoginSecondStep,
			Username:      user.Username,
			Token:         "",
			DeviceInfo:    ctx.Request.Header.Get("User-Agent"),
			IP:            ctx.ClientIP(),
			Approved:      true,
			ApproveMethod: db.Email,
			CreatedAt:     time.Now(),
		}
		err = s.store.InsertLog(&reqLog)
		if err != nil {
			return nil, ErrInternalServer
		}

		resp = &AuthVerificationResponse{
			AccessToken:           accessToken,
			AccessTokenExpiresAt:  accessTokenPayload.ExpiredAt,
			RefreshToken:          refreshToken,
			RefreshTokenExpiresAt: refreshTokenPayload.ExpiredAt,
			UserInformation: UserInformation{
				Username:  user.Username,
				Email:     user.Email,
				CreatedAt: user.CreatedAt,
				UpdatedAt: user.UpdatedAt,
				DeletedAt: time.Time{},
			},
			TOTPSecret: totpSecret,
		}

		return nil, nil
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func (s *Server) GetLoginRequests(ctx *gin.Context) {
	var req *GetLoginRequests
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	// decode the access token
	payload, err := s.tokenMaker.VerifyToken(req.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}

	loginRequest, err := s.cache.GetData(payload.Username)
	if err != nil || loginRequest == nil {
		ctx.JSON(http.StatusNotFound, ErrInvalidRequest)
		return
	}

	codesMap := map[string]string{}
	codesMap[loginRequest["code"].(string)] = loginRequest["code"].(string)

	count := 0
	for {
		code := fmt.Sprintf("%02d", rand.Intn(100))
		_, ok := codesMap[code]
		if !ok {
			codesMap[code] = code
			count++

			if count == 2 {
				break
			}
		}
	}

	codes := make([]string, len(codesMap))
	index := 0
	for key, _ := range codesMap {
		codes[index] = key
		index++
	}

	parsedTime, err := time.Parse(time.RFC3339Nano, loginRequest["time"].(string))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		log.Error().Err(err)
		return
	}

	response := &LoginApproves{
		Codes:      codes,
		IP:         loginRequest["ip"].(string),
		DeviceInfo: loginRequest["device_info"].(string),
		Time:       parsedTime,
	}

	ctx.JSON(http.StatusOK, response)
}

func (s *Server) ApproveLoginRequests(ctx *gin.Context) {
	var req *ApproveLoginRequests
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	// decode the access token
	payload, err := s.tokenMaker.VerifyToken(req.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}

	loginRequest, err := s.cache.GetData(payload.Username)
	if err != nil {
		ctx.JSON(http.StatusNotFound, nil)
		return
	}

	approved := 2
	code := loginRequest["code"]
	if code == req.Code {
		approved = 1
	}
	loginRequest["approved"] = strconv.Itoa(approved)

	err = s.cache.SetData(payload.Username, loginRequest, time.Minute*2)
	if err != nil {
		ctx.Status(http.StatusInternalServerError)
		return
	}

	ctx.Status(http.StatusOK)
}

func (s *Server) RefreshToken(ctx *gin.Context) {
	var req *RefreshTokenRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	// decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.RefreshToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}

	accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
		&token.Payload{
			Username:  payload.Username,
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(15 * time.Minute),
		})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, ErrInternalServer)
		return
	}

	ctx.JSON(http.StatusOK, &RefreshTokenResponse{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: accessTokenPayload.ExpiredAt,
	})
}

func (s *Server) GetApproveLogs(ctx *gin.Context) {
	var req *GetApproveLogsResp
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	payload, err := s.tokenMaker.VerifyToken(req.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}

	logs, err := s.store.GetLogs(
		bson.D{
			{
				"username", payload.Username,
			},
			{
				"type", db.LoginSecondStepAppApprove,
			},
		},
		bson.D{
			{
				"created_at", db.Descending,
			},
		},
		50,
		1,
	)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	resp := make([]ApproveLog, len(logs))
	for index, l := range logs {
		resp[index] = ApproveLog{
			Username:    l.Username,
			DeviceInfo:  l.DeviceInfo,
			IP:          l.Username,
			Approved:    l.Approved,
			RedirectUrl: l.RedirectUrl,
			CreatedAt:   l.CreatedAt,
		}
	}

	ctx.JSON(http.StatusOK, resp)
}

func errorResponse(err error) gin.H {
	return gin.H{"message": err.Error()}
}
