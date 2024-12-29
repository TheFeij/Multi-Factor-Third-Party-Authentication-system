package api

import (
	"authentication-server/service/db"
	"authentication-server/service/tokenmanager/token"
	util2 "authentication-server/service/util"
	worker2 "authentication-server/service/worker"
	"errors"
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
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
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
			return nil, fmt.Errorf("failed to hash password: %v", err)
		}

		// Step 2: Create the user model
		tempUser = ConvertSignupRequestToModel(req)
		tempUser.Password = hashedPassword
		tempUser.SecretCode = util2.RandomString(6, util2.NUMBERS)
		tempUser.ExpiredAt = time.Now().Add(24 * time.Hour)

		// Step 3: Insert the user into the database
		err = s.store.InsertTempUserWithSession(sessCtx, tempUser) // Use the session-aware insert method
		if err != nil {
			return nil, fmt.Errorf("failed to insert user: %v", err)
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
			return nil, fmt.Errorf("failed to enqueue email task: %v", err)
		}

		return nil, nil
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
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
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	// decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.SignupToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
		return
	}
	if payload.ExpiredAt.Before(time.Now()) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("token expired")))
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
			return nil, fmt.Errorf("token expired")
		}

		// check the code
		if tempUser.SecretCode != req.VerificationCode {
			return nil, fmt.Errorf("wrong code")
		}

		// if correct delete the temp user and insert user
		err = s.store.DeleteTempUserWithSession(sessCtx, tempUser.ID)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}

		// create key for TOTP generation
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "MFA",
			AccountName: tempUser.Username,
		})
		if err != nil {
			log.Error().Msg(fmt.Sprintf("Failed to generate TOTP key: %v", err))
		}

		cipherKey, err := util2.Encrypt(key.Secret(), s.configs.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt")
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
			return nil, fmt.Errorf("wrong code")
		}

		// creating tokens
		refreshToken, refreshTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: time.Now().Add(30 * 24 * time.Hour),
			})
		if err != nil {
			return nil, fmt.Errorf("failed to create refresh token")
		}

		accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: time.Now().Add(15 * time.Minute),
			})
		if err != nil {
			return nil, fmt.Errorf("failed to create refresh token")
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
			return nil, fmt.Errorf("failed to create session")
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
	}

	ctx.JSON(http.StatusOK, resp)
}

func (s *Server) Login(ctx *gin.Context) {
	var req *LoginRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	if err := ValidateOnLogin(s.store, req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	clientIDInt, err := strconv.ParseInt(req.ClientID, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
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
			return nil, errors.New("failed to remove older requests")
		}

		err = s.store.InsertThirdPartyLoginRequests(sessCtx, &db.ThirdPartyLoginRequests{
			ClientID:    clientIDInt,
			RedirectUrl: req.RedirectUri,
			Username:    user.Username,
			CreatedAt:   time.Now(),
			ExpiresAt:   time.Now().Add(10 * time.Minute),
		})
		if err != nil {
			return nil, errors.New("failed to insert request")
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
			return nil, errors.New("failed to create login token")
		}

		return nil, nil
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	ctx.JSON(http.StatusOK, &AndroidLoginResponse{LoginToken: loginToken})
}

func (s *Server) AndroidAppLogin(ctx *gin.Context) {
	var req *LoginRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
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
			ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidCredentials))
			return nil, err
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
			return nil, fmt.Errorf("failed to insert user: %v", err)
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
			return nil, fmt.Errorf("failed to enqueue email task: %v", err)
		}

		return nil, nil
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
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
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
	}

	now := time.Now()

	// decode the login token
	payload, err := s.tokenMaker.VerifyToken(req.LoginToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
		return
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("token expired")))
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
			return nil, fmt.Errorf("token expired")
		}

		// check the code
		if tempUser.SecretCode != req.VerificationCode {
			return nil, fmt.Errorf("wrong code")
		}

		user, err = s.store.GetUserByUsername(tempUser.Username)

		// if correct delete the temp user and insert user
		err = s.store.DeleteTempUserWithSession(sessCtx, tempUser.ID)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}

		totpSecret, err := util2.Decrypt(user.TOTPSecret, s.configs.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt")
		}

		// creating tokens
		refreshToken, refreshTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: now.Add(30 * 24 * time.Hour),
			})
		if err != nil {
			return nil, fmt.Errorf("failed to create refresh token")
		}

		accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
			&token.Payload{
				Username:  user.Username,
				IssuedAt:  time.Now(),
				ExpiredAt: now.Add(15 * time.Minute),
			})
		if err != nil {
			return nil, fmt.Errorf("failed to create refresh token")
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
			return nil, fmt.Errorf("failed to create session")
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
	}

	ctx.JSON(http.StatusOK, resp)
}

func (s *Server) VerifyLoginWithTOTP(ctx *gin.Context) {
	var req *VerifyLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
	}

	clientIDInt, err := strconv.ParseInt(req.ClientID, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	now := time.Now()

	// decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.LoginToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("token expired")))
	}

	err = s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		user, err := s.store.GetUserWithSession(sessCtx, payload.ID)
		if err != nil {
			return nil, err
		}

		totpKey, err := util2.Decrypt(user.TOTPSecret, s.configs.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key")
		}

		isValid := totp.Validate(req.TOTP, totpKey)
		if !isValid {
			ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("invalid TOTP code")))
		}

		thirdPartyRequest, err := s.store.GetThirdPartyLoginRequests(user.Username, clientIDInt)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("invalid clientID")))
		}
		if thirdPartyRequest.ExpiresAt.Before(time.Now()) {
			ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("request expired")))
		}
		req.RedirectUri = thirdPartyRequest.RedirectUrl

		return nil, err
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
	}

	// Generate an authorization code
	authCode, _, err := s.tokenMaker.CreateToken(&token.Payload{
		ID:        payload.ID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authorization code"})
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
		err := conn.WriteMessage(websocket.TextMessage, []byte("Invalid request"))
		if err != nil {
			return
		}
		return
	}

	clientIDInt, err := strconv.ParseInt(req.ClientID, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	// Decode the login token
	payload, err := s.tokenMaker.VerifyToken(req.LoginToken)
	if err != nil {
		err := conn.WriteJSON(errorResponse(fmt.Errorf("unauthorized: %v", err)))
		if err != nil {
			return
		}
		return
	}
	if payload.ExpiredAt.Before(time.Now()) {
		err := conn.WriteJSON(errorResponse(fmt.Errorf("token expired")))
		if err != nil {
			return
		}
		return
	}

	user, err := s.store.GetUser(payload.ID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(errors.New("user not found")))
	}

	thirdPartyRequest, err := s.store.GetThirdPartyLoginRequests(user.Username, clientIDInt)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("invalid clientID")))
		return
	}
	if thirdPartyRequest.ExpiresAt.Before(time.Now()) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("request expired")))
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
		err := conn.WriteJSON(errorResponse(fmt.Errorf("failed to save code: %v", err)))
		if err != nil {
			return
		}
		return
	}

	// Send the code to the client
	if err := conn.WriteJSON(map[string]string{
		"message": "Login approval required",
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

	// Generate an authorization code
	authCode, _, err := s.tokenMaker.CreateToken(&token.Payload{
		ID:        user.ID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authorization code"})
		return
	}

	// Redirect to the callback URI with the authorization code
	redirectURL := fmt.Sprintf("%s?token=%s", req.RedirectUri, authCode)
	ctx.JSON(http.StatusOK, gin.H{
		"redirect_url": redirectURL,
	})
}

func (s *Server) GetLoginRequests(ctx *gin.Context) {
	var req *GetLoginRequests
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
	}

	now := time.Now()

	// decode the access token
	payload, err := s.tokenMaker.VerifyToken(req.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("token expired")))
	}

	loginRequest, err := s.cache.GetData(payload.Username)
	if err != nil || loginRequest == nil {
		ctx.JSON(http.StatusNotFound, nil)
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
		log.Error().Err(err)
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
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
	}

	now := time.Now()

	// decode the access token
	payload, err := s.tokenMaker.VerifyToken(req.AccessToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("token expired")))
	}

	loginRequest, err := s.cache.GetData(payload.Username)
	if err != nil {
		ctx.JSON(http.StatusNotFound, nil)
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
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
	}

	now := time.Now()

	// decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.RefreshToken)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
		return
	}
	if payload.ExpiredAt.Before(now) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(errors.New("token expired")))
	}

	accessToken, accessTokenPayload, err := s.tokenMaker.CreateToken(
		&token.Payload{
			Username:  payload.Username,
			IssuedAt:  time.Now(),
			ExpiredAt: now.Add(15 * time.Minute),
		})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(errors.New("failed to create refresh token")))
	}

	ctx.JSON(http.StatusOK, &RefreshTokenResponse{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: accessTokenPayload.ExpiredAt,
	})
}

func errorResponse(err error) gin.H {
	return gin.H{"message": err.Error()}
}
