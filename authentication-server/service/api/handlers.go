package api

import (
	"authentication-server/service/db"
	"authentication-server/service/tokenmanager/token"
	util2 "authentication-server/service/util"
	worker2 "authentication-server/service/worker"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/hibiken/asynq"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/mongo"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Adjust this for security, e.g., domain checks
	},
}

func (s *Server) Signup(ctx *gin.Context) {
	var req *SignupRequest

	// Bind JSON input to request struct
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	if err := ValidateOnSignup(s.store, req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	var tempUser *db.TempUser
	// Start a MongoDB session for the transaction
	err := s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		// Step 1: Hash the password
		hashedPassword, err := util2.HashPassword(req.Password)
		if err != nil {
			return nil, ErrInternalServer
		}

		// Step 2: Create the user model
		tempUser = ConvertSignupRequestToModel(req)
		tempUser.Password = hashedPassword
		tempUser.SecretCode = util2.RandomString(6, util2.NUMBERS)
		tempUser.ExpiredAt = time.Now().Add(24 * time.Hour)

		// Step 3: Insert the user into the database
		err = s.store.InsertTempUserWithSession(sessCtx, tempUser) // Use the session-aware insert method
		if err != nil {
			return nil, ErrInternalServer
		}

		// Step 4: Enqueue the task for sending the verification email
		taskPayload := &worker2.SendVerificationEmailPayload{ID: tempUser.ID}
		opts := []asynq.Option{
			asynq.MaxRetry(10),
			asynq.ProcessIn(time.Second),
			asynq.Queue(worker2.CriticalQueue),
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

	signupToken, _, err := s.tokenMaker.CreateToken(
		&token.Payload{
			ID:        tempUser.ID,
			Username:  "",
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(24 * time.Hour),
		},
	)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	ctx.JSON(http.StatusOK, &SignupResponse{SignupToken: signupToken})
}

func (s *Server) VerifyEmail(ctx *gin.Context) {
	var req *VerifyEmailRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	// decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.SignupToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}
	if payload.ExpiredAt.Before(time.Now()) {
		ctx.JSON(http.StatusUnauthorized, ErrExpiredSignupToken)
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
		if tempUser.ExpiredAt.Before(time.Now()) {
			return nil, ErrExpiredSignupToken
		}

		// check the code
		if tempUser.SecretCode != req.VerificationCode {
			return nil, ErrInvalidTOTP
		}

		// if correct delete the temp user and insert user
		err = s.store.DeleteTempUserWithSession(sessCtx, tempUser.ID)
		if err != nil {
			return nil, ErrInternalServer
		}

		// create key for TOTP generation
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "MFA",
			AccountName: tempUser.Username,
		})
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Failed to generate TOTP key: %v", err))
			return nil, ErrInternalServer
		}

		cipherKey, err := util2.Encrypt(key.Secret(), s.configs.EncryptionKey)
		if err != nil {
			return nil, ErrInternalServer
		}

		// create private key to generate TOTPs send to the user with tokens
		user = &db.User{
			Username:   tempUser.Username,
			Email:      tempUser.Email,
			Password:   tempUser.Password,
			TOTPSecret: cipherKey,
		}
		err = s.store.InsertUserWithSession(sessCtx, user)
		if err != nil {
			return nil, ErrInternalServer
		}

		// creating tokens
		refreshToken, refreshTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: time.Now().Add(30 * 24 * time.Hour),
			})
		if err != nil {
			return nil, ErrInternalServer
		}

		accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: time.Now().Add(15 * time.Minute),
			})
		if err != nil {
			return nil, ErrInternalServer
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
			return nil, ErrInternalServer
		}

		resp = &AuthVerificationResponse{
			AccessToken:           accessToken,
			AccessTokenExpiresAt:  accessTokenPayload.ExpiredAt,
			RefreshToken:          refreshToken,
			RefreshTokenExpiresAt: refreshTokenPayload.ExpiredAt,
			SessionID:             session.ID,
			UserInformation: UserInformation{
				Username:  user.Username,
				Email:     user.Email,
				CreatedAt: user.CreatedAt,
				UpdatedAt: user.UpdatedAt,
				DeletedAt: time.Time{},
			},
			TOTPSecret: key.Secret(),
		}

		return nil, nil
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func (s *Server) Login(ctx *gin.Context) {
	var req *LoginRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	if err := ValidateOnLogin(s.store, req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	clientIDInt, err := strconv.ParseInt(req.ClientID, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	var user *db.User

	if req.Username != "" {
		user, err = s.store.GetUserByUsernameAndPassword(req.Username, req.Password)
	} else {
		user, err = s.store.GetUserByEmailAndPassword(req.Email, req.Password)
	}
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, ErrInvalidCredentials)
		return
	}

	var loginToken string
	err = s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		err = s.store.RemoveThirdPartyLoginRequest(sessCtx, req.Username, req.ClientID)
		if err != nil {
			return nil, ErrInternalServer
		}

		err = s.store.InsertThirdPartyLoginRequests(sessCtx, &db.ThirdPartyLoginRequests{
			ClientID:    clientIDInt,
			RedirectUrl: req.RedirectUri,
			Username:    user.Username,
			CreatedAt:   time.Now(),
			ExpiresAt:   time.Now().Add(10 * time.Minute),
		})
		if err != nil {
			return nil, ErrInternalServer
		}

		// creating tokens
		loginToken, _, err = s.tokenMaker.CreateToken(
			&token.Payload{
				ID:        user.ID,
				Username:  "",
				IssuedAt:  time.Now(),
				ExpiredAt: time.Now().Add(10 * time.Minute),
			},
		)
		if err != nil {
			return nil, ErrInternalServer
		}

		return nil, nil
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, &AndroidLoginResponse{LoginToken: loginToken})
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
			SecretCode: util2.RandomString(6, util2.NUMBERS),
		}

		// Step 3: Insert the user into the database
		err = s.store.InsertTempUserWithSession(sessCtx, tempUser) // Use the session-aware insert method
		if err != nil {
			return nil, ErrInternalServer
		}

		// Step 4: Enqueue the task for sending the verification email
		taskPayload := &worker2.SendVerificationEmailPayload{ID: tempUser.ID}
		opts := []asynq.Option{
			asynq.MaxRetry(10),
			asynq.ProcessIn(time.Second),
			asynq.Queue(worker2.CriticalQueue),
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
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrExpiredLoginToken))
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

		totpSecret, err := util2.Decrypt(user.TOTPSecret, s.configs.EncryptionKey)
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
			return nil, ErrInternalServer
		}

		resp = &AuthVerificationResponse{
			AccessToken:           accessToken,
			AccessTokenExpiresAt:  accessTokenPayload.ExpiredAt,
			RefreshToken:          refreshToken,
			RefreshTokenExpiresAt: refreshTokenPayload.ExpiredAt,
			SessionID:             session.ID,
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

func (s *Server) VerifyLoginWithTOTP(ctx *gin.Context) {
	var req *VerifyLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	clientIDInt, err := strconv.ParseInt(req.ClientID, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	now := time.Now()

	// decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.LoginToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrTokenExpired))
		return
	}

	err = s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		user, err := s.store.GetUserWithSession(sessCtx, payload.ID)
		if err != nil {
			return nil, ErrUserNotFound
		}

		totpKey, err := util2.Decrypt(user.TOTPSecret, s.configs.EncryptionKey)
		if err != nil {
			return nil, ErrInternalServer
		}

		isValid := totp.Validate(req.TOTP, totpKey)
		if !isValid {
			return nil, ErrInvalidTOTP
		}

		thirdPartyRequest, err := s.store.GetThirdPartyLoginRequests(user.Username, clientIDInt)
		if err != nil {
			return nil, ErrInvalidRequest
		}
		if thirdPartyRequest.ExpiresAt.Before(time.Now()) {
			return nil, ErrExpiredLoginToken
		}
		req.RedirectUri = thirdPartyRequest.RedirectUrl

		return nil, nil
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	// Generate an authorization code
	authCode, _, err := s.tokenMaker.CreateToken(&token.Payload{
		ID:        payload.ID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	// Redirect to the callback URI with the authorization code
	redirectURL := fmt.Sprintf("%s?token=%s", req.RedirectUri, authCode)
	ctx.JSON(http.StatusOK, gin.H{
		"redirect_url": redirectURL,
	})
}

func (s *Server) VerifyLoginWithAndroidAppNotification(ctx *gin.Context) {
	// Upgrade the HTTP connection to a WebSocket
	conn, err := upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	defer conn.Close()

	// Read the initial login request from the WebSocket
	var req VerifyLoginRequest
	if err := conn.ReadJSON(&req); err != nil {
		err := conn.WriteMessage(websocket.TextMessage, []byte(ErrInvalidRequest.Error()))
		if err != nil {
			return
		}
		return
	}

	clientIDInt, err := strconv.ParseInt(req.ClientID, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	// Decode the login token
	payload, err := s.tokenMaker.VerifyToken(req.LoginToken)
	if err != nil {
		err := conn.WriteJSON(ErrInvalidRequest)
		if err != nil {
			return
		}
		return
	}
	if payload.ExpiredAt.Before(time.Now()) {
		err := conn.WriteJSON(ErrExpiredLoginToken)
		if err != nil {
			return
		}
		return
	}

	user, err := s.store.GetUser(payload.ID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrUserNotFound))
		return
	}

	thirdPartyRequest, err := s.store.GetThirdPartyLoginRequests(user.Username, clientIDInt)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrExpiredSignupToken))
		return
	}
	if thirdPartyRequest.ExpiresAt.Before(time.Now()) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrExpiredSignupToken))
		return
	}
	req.RedirectUri = thirdPartyRequest.RedirectUrl

	// Generate a 2-digit code
	code := fmt.Sprintf("%02d", rand.Intn(100))

	// Collect device and location info
	deviceInfo := ctx.Request.Header.Get("User-Agent")
	ip := ctx.ClientIP() // Requires Gin framework setup

	// Store the code temporarily (e.g., in Redis or an in-memory store)
	err = s.cache.SetData(user.Username, map[string]interface{}{
		"code":        code,
		"approved":    "0",
		"time":        time.Now(),
		"device_info": deviceInfo,
		"ip":          ip,
	}, time.Minute*2)
	if err != nil {
		err := conn.WriteJSON(errorResponse(ErrInternalServer))
		if err != nil {
			return
		}
		return
	}

	// Send the code to the client
	if err := conn.WriteJSON(map[string]string{
		"message": "احراز هویت با موفقیت انجام شد",
		"code":    code,
	}); err != nil {
		return
	}

	var approved int64

	start := time.Now()
	for time.Since(start) < 2*time.Minute {
		time.Sleep(4 * time.Second)
		data, err := s.cache.GetData(user.Username)
		if err != nil {
			time.Sleep(4 * time.Second)
			continue
		}

		value := data["approved"].(string)
		log.Info().Msg(value)
		if value == "1" || value == "2" {
			approved, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return
			}
			break
		}
	}

	if err := conn.WriteJSON(map[string]any{
		"approved": approved,
	}); err != nil {
		return
	}

	if approved == 1 { // Approved
		authCode, _, err := s.tokenMaker.CreateToken(&token.Payload{
			ID:        user.ID,
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(10 * time.Minute),
		})
		if err != nil {
			conn.WriteJSON(errorResponse(ErrInternalServer))
			return
		}

		redirectURL := fmt.Sprintf("%s?token=%s", req.RedirectUri, authCode)
		conn.WriteJSON(map[string]any{
			"approved":     approved,
			"redirect_url": redirectURL,
		})
	} else if approved == 2 { // Rejected
		conn.WriteJSON(map[string]any{
			"approved": approved,
			"error":    "ورود تایید نشد",
		})
	}
}

func (s *Server) GetLoginRequests(ctx *gin.Context) {
	var req *GetLoginRequests
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	now := time.Now()

	// decode the access token
	payload, err := s.tokenMaker.VerifyToken(req.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrTokenExpired))
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

	now := time.Now()

	// decode the access token
	payload, err := s.tokenMaker.VerifyToken(req.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrTokenExpired))
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

	now := time.Now()

	// decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.RefreshToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, ErrTokenExpired)
		return
	}

	accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
		&token.Payload{
			Username:  payload.Username,
			IssuedAt:  time.Now(),
			ExpiredAt: now.Add(15 * time.Minute),
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

func errorResponse(err error) gin.H {
	return gin.H{"message": err.Error()}
}
