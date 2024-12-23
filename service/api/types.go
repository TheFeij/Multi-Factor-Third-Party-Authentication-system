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
	LoginToken  string `json:"login_token"`
	TOTP        string `json:"totp"`
	ClientID    string `json:"client_id"`
	RedirectUri string `json:"redirect_uri"`
}

type VerifyAndroidLoginRequest struct {
	LoginToken       string `json:"login_token"`
	VerificationCode string `json:"verification_code"`
}

type LoginRequest struct {
	Username    string `json:"username,omitempty"`
	Email       string `json:"email,omitempty"`
	Password    string `json:"password,omitempty"`
	ClientID    string `json:"client_id"`
	RedirectUri string `json:"redirect_uri"`
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

type GetUserRequest struct {
	AccessToken string `json:"access_token,omitempty"`
}

type GetUserResponse struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
}
