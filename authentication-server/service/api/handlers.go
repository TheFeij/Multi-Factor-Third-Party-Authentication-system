package api

import (
	"authentication-server/service/db"
	"authentication-server/service/tokenmanager/token"
	util2 "authentication-server/service/util"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
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

func (s *Server) Login(ctx *gin.Context) {
	var req *LoginRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to unmarshal request")
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	if err := ValidateOnLogin(s.store, req); err != nil {
		log.Error().Err(err).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("validation failed")
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	clientIDInt, err := strconv.ParseInt(req.ClientID, 10, 64)
	if err != nil {
		log.Error().Err(err).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to Parse client id")
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
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidCredentials))
		return
	}

	var loginToken string
	err = s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		err = s.store.InsertThirdPartyLoginRequest(sessCtx, &db.ThirdPartyLoginRequest{
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

	reqLog := db.Log{
		Type:            db.LoginFirstStep,
		Username:        user.Username,
		Token:           loginToken,
		DeviceInfo:      ctx.Request.Header.Get("User-Agent"),
		IP:              ctx.ClientIP(),
		ClientWebsiteID: req.ClientID,
		RedirectUrl:     req.RedirectUri,
		CreatedAt:       time.Now(),
	}
	err = s.store.InsertLog(&reqLog)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	ctx.JSON(http.StatusOK, &AndroidLoginResponse{LoginToken: loginToken})
}

func (s *Server) VerifyLoginWithTOTP(ctx *gin.Context) {
	var req *VerifyLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("unmarshalling request failed")
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	clientIDInt, err := strconv.ParseInt(req.ClientID, 10, 64)
	if err != nil {
		log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to parse client id")
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		return
	}

	now := time.Now()

	// decode the signup token
	payload, err := s.tokenMaker.VerifyToken(req.LoginToken)
	if err != nil {
		log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to decode token")
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrInvalidRequest))
		return
	}
	if payload.ExpiredAt.Before(now) {
		log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("token expired")
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrTokenExpired))
		return
	}

	var user *db.User

	err = s.store.Transaction(ctx, func(sessCtx mongo.SessionContext) (interface{}, error) {
		user, err = s.store.GetUserWithSession(sessCtx, payload.ID)
		if err != nil {
			log.Error().Err(err).Str("payload", fmt.Sprintf("%+v", payload)).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to get user")
			return nil, ErrUserNotFound
		}

		totpKey, err := util2.Decrypt(user.TOTPSecret, s.configs.EncryptionKey)
		if err != nil {
			log.Error().Err(err).Str("user", fmt.Sprintf("%+v", user)).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to decrypt totp key")
			return nil, ErrInternalServer
		}

		isValid := totp.Validate(req.TOTP, totpKey)
		if !isValid {
			log.Error().Err(err).Str("totp-key", fmt.Sprintf("%+v", totpKey)).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("totp ket invalid")

			reqLog := db.Log{
				Type:            db.LoginSecondStepTOTP,
				Username:        user.Username,
				Token:           "",
				DeviceInfo:      ctx.Request.Header.Get("User-Agent"),
				IP:              ctx.ClientIP(),
				Approved:        false,
				ApproveMethod:   db.TOTP,
				ClientWebsiteID: req.ClientID,
				RedirectUrl:     req.RedirectUri,
				CreatedAt:       time.Now(),
			}
			err = s.store.InsertLog(&reqLog)
			if err != nil {
				return nil, ErrInvalidTOTP
			}

			return nil, ErrInvalidTOTP
		}

		thirdPartyRequest, err := s.store.GetThirdPartyLoginRequestWithSession(sessCtx, user.Username, clientIDInt)
		if err != nil {
			log.Error().Err(err).Str("client-id", fmt.Sprintf("%+v", clientIDInt)).Str("user", fmt.Sprintf("%+v", user)).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to get third party request")
			return nil, ErrInvalidRequest
		}
		if thirdPartyRequest.ExpiresAt.Before(time.Now()) {
			log.Error().Err(err).Str("third-party-req", fmt.Sprintf("%+v", thirdPartyRequest)).Str("user", fmt.Sprintf("%+v", user)).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("third party request expired")
			return nil, ErrExpiredLoginToken
		}
		req.RedirectUri = thirdPartyRequest.RedirectUrl

		return nil, nil
	})
	if err != nil {
		log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("transaction failed")
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
		log.Error().Err(err).Str("req", fmt.Sprintf("%+v", req)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("failed to create auth token")
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	reqLog := db.Log{
		Type:            db.LoginSecondStepAppApprove,
		Username:        user.Username,
		Token:           authCode,
		DeviceInfo:      ctx.Request.Header.Get("User-Agent"),
		IP:              ctx.ClientIP(),
		Approved:        true,
		ApproveMethod:   db.TOTP,
		ClientWebsiteID: req.ClientID,
		RedirectUrl:     req.RedirectUri,
		CreatedAt:       time.Now(),
	}
	err = s.store.InsertLog(&reqLog)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	log.Info().Str("req", fmt.Sprintf("%+v", req)).Str("auth-token", fmt.Sprintf("%+v", authCode)).Str("API", ctx.Request.Method).Str("IP", ctx.ClientIP()).Time("timestamp", time.Now()).Msg("auth token created")

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
		log.Error().Err(err).Msg(err.Error())
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	defer conn.Close()

	// Read the initial login request from the WebSocket
	var req VerifyLoginRequest
	if err := conn.ReadJSON(&req); err != nil {
		log.Error().Err(err).Msg(err.Error())
		err := conn.WriteMessage(websocket.TextMessage, []byte(ErrInvalidRequest.Error()))
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return
		}
		return
	}

	clientIDInt, err := strconv.ParseInt(req.ClientID, 10, 64)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(ErrInvalidRequest))
		log.Error().Err(err).Msg(err.Error())
		return
	}

	// Decode the login token
	payload, err := s.tokenMaker.VerifyToken(req.LoginToken)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
		err := conn.WriteJSON(ErrInvalidRequest)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return
		}
		return
	}
	if payload.ExpiredAt.Before(time.Now()) {
		err := conn.WriteJSON(ErrExpiredLoginToken)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return
		}
		log.Error().Msg("expired")
		return
	}

	user, err := s.store.GetUser(payload.ID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrUserNotFound))
		log.Error().Err(err).Msg(err.Error())

		return
	}

	thirdPartyRequest, err := s.store.GetThirdPartyLoginRequest(user.Username, clientIDInt)
	if err != nil {
		log.Error().Err(err).Msg(err.Error())
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrExpiredSignupToken))
		return
	}
	if thirdPartyRequest.ExpiresAt.Before(time.Now()) {
		ctx.JSON(http.StatusUnauthorized, errorResponse(ErrExpiredSignupToken))
		log.Error().Msg("expired2")
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
		log.Error().Err(err).Msg(err.Error())
		err := conn.WriteJSON(errorResponse(ErrInternalServer))
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			return
		}
		return
	}

	// Send the code to the client
	if err := conn.WriteJSON(map[string]string{
		"message": "احراز هویت با موفقیت انجام شد",
		"code":    code,
	}); err != nil {
		log.Error().Err(err).Msg(err.Error())
		return
	}

	var approved int64

	start := time.Now()
	for time.Since(start) < 2*time.Minute {
		time.Sleep(4 * time.Second)
		data, err := s.cache.GetData(user.Username)
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			time.Sleep(4 * time.Second)
			continue
		}

		value := data["approved"].(string)
		log.Info().Msg(value)
		if value == "1" || value == "2" {
			approved, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				log.Error().Err(err).Msg(err.Error())
				return
			}
			break
		}
	}

	if err := conn.WriteJSON(map[string]any{
		"approved": approved,
	}); err != nil {
		log.Error().Err(err).Msg(err.Error())
		return
	}

	var authToken string

	if approved == 1 { // Approved
		authToken, _, err = s.tokenMaker.CreateToken(&token.Payload{
			ID:        user.ID,
			IssuedAt:  time.Now(),
			ExpiredAt: time.Now().Add(10 * time.Minute),
		})
		if err != nil {
			log.Error().Err(err).Msg(err.Error())
			conn.WriteJSON(errorResponse(ErrInternalServer))
			return
		}

		redirectURL := fmt.Sprintf("%s?token=%s", req.RedirectUri, authToken)
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

	err = s.cache.DeleteData(user.Username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	reqLog := db.Log{
		Type:            db.LoginSecondStepAppApprove,
		Username:        user.Username,
		Token:           authToken,
		DeviceInfo:      deviceInfo,
		IP:              ip,
		Approved:        false,
		ApproveMethod:   db.AppApprove,
		ClientWebsiteID: req.ClientID,
		RedirectUrl:     req.RedirectUri,
		CreatedAt:       time.Time{},
		ExpiresAt:       time.Time{},
	}
	if approved == 1 {
		reqLog.Approved = true
	}

	err = s.store.InsertLog(&reqLog)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(ErrInternalServer))
		return
	}

	ctx.Status(http.StatusOK)
}

func errorResponse(err error) gin.H {
	return gin.H{"message": err.Error()}
}
