package api

import (
	"admin-server/tokenmanager/token"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

const (
	authorizationHeaderKey  string = "authorization"
	authorizationPayloadKey string = "authorization_payload"
	authorizationTypeBearer string = "bearer"
)

func authMiddleWare(tokenMaker *token.PasetoMaker) gin.HandlerFunc {
	return func(context *gin.Context) {
		authorizationHeader := context.GetHeader(authorizationHeaderKey)
		if len(authorizationHeader) == 0 {
			err := fmt.Errorf("athorization header is not provided")
			context.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse(err))
			return
		}

		fields := strings.Fields(authorizationHeader)
		if len(fields) < 2 {
			err := fmt.Errorf("invalid authorization format")
			context.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse(err))
			return
		}

		authorizationType := fields[0]
		if strings.ToLower(authorizationType) != authorizationTypeBearer {
			err := fmt.Errorf("invalid authorization header format")
			context.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse(err))
			return
		}

		accessToken := fields[1]
		payload, err := tokenMaker.VerifyToken(accessToken)
		if err != nil {
			context.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse(err))
			return
		}

		context.Set(authorizationPayloadKey, payload)
		context.Next()
	}
}
