package api

import "time"

type GetAllReq struct {
	Page     int64
	PageSize int64
}

type User struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	Password   string    `json:"password"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	TOTPSecret string    `json:"totp_secret"`
}

type LoginReq struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type LoginResp struct {
	LoginToken string `json:"login_token,omitempty"`
}
