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

type VerifyAndroidLoginRequest struct {
	LoginToken       string `json:"login_token"`
	VerificationCode string `json:"verification_code"`
}

type LoginRequest struct {
	Username string `json:"username,omitempty"  binding:"validUsername"`
	Email    string `json:"email,omitempty"  binding:"ValidEmail"`
	Password string `json:"password,omitempty"  binding:"validPassword"`
}

type SignupRequest struct {
	Username string `json:"username" binding:"validUsername"`
	Password string `json:"password" binding:"validPassword"`
	Email    string `json:"email" binding:"ValidEmail"`
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

type AndroidLoginResponse struct {
	LoginToken string `json:"login_token,omitempty"`
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

type ApproveLoginRequests struct {
	AccessToken string `json:"access_token"`
	Code        string `json:"code"`
}

type LoginApproves struct {
	Codes      []string  `json:"codes,omitempty"`
	IP         string    `json:"ip,omitempty"`
	DeviceInfo string    `json:"device_info,omitempty"`
	Time       time.Time `json:"time"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenResponse struct {
	AccessToken          string    `json:"access_token,omitempty"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at"`
}
