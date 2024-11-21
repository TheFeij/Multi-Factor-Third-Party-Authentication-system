package api

import (
	"Third-Party-Multi-Factor-Authentication-System/db"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type LoginRequest struct {
	Username string
	Email    string
	Password string
}

type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Email    string `json:"email"`
}

type SignupResponse struct {
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
	SessionID             primitive.ObjectID
	UserInformation       UserInformation
}

type UserInformation struct {
	Username  string    `json:"username"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	DeletedAt time.Time `json:"deleted_at"`
}

func ConvertSignupRequestToModel(req *SignupRequest) *db.User {
	return &db.User{
		Username: req.Username,
		Name:     req.Name,
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
