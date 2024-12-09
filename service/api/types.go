package api

import (
	"Third-Party-Multi-Factor-Authentication-System/service/db"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type VerifyEmailRequest struct {
	SignupToken      string `json:"signup_token"`
	VerificationCode string `json:"verification_code"`
}

type VerifyLoginRequest struct {
	LoginToken string `json:"login_token"`
	TOTP       string `json:"totp"`
}

type LoginRequest struct {
	Username string
	Email    string
	Password string
}

type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type AuthVerificationResponse struct {
	AccessToken           string             `json:"access_token,omitempty"`
	AccessTokenExpiresAt  time.Time          `json:"access_token_expires_at"`
	RefreshToken          string             `json:"refresh_token,omitempty"`
	RefreshTokenExpiresAt time.Time          `json:"refresh_token_expires_at"`
	SessionID             primitive.ObjectID `json:"session_id,omitempty"`
	UserInformation       UserInformation    `json:"user_information"`
	TOTPSecret            string             `json:"totp_secret" json:"totp_secret,omitempty"`
}

type SignupResponse struct {
	SignupToken string `json:"signup_token,omitempty"`
}

type UserInformation struct {
	Username  string    `json:"username"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	DeletedAt time.Time `json:"deleted_at"`
}

func ConvertSignupRequestToModel(req *SignupRequest) *db.TempUser {
	return &db.TempUser{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	}
}

func ConvertLoginRequestToModel(req *LoginRequest) *db.User {
	return &db.User{
		Username: req.Username,
		Password: req.Password,
	}
}

type GetLoginRequests struct {
	AccessToken string `json:"access_token"`
}

type LoginApproves struct {
	Codes      []string  `json:"codes,omitempty"`
	IP         string    `json:"ip,omitempty"`
	DeviceInfo string    `json:"device_info,omitempty"`
	Time       time.Time `json:"time"`
}
