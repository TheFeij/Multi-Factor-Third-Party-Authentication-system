package db

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

// User model with BSON tags
type User struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"` // MongoDB will automatically generate an ObjectID
	Username   string             `bson:"username"`
	Email      string             `bson:"email"`
	Password   string             `bson:"password"`
	CreatedAt  time.Time          `bson:"created_at"`
	UpdatedAt  time.Time          `bson:"updated_at"`
	DeletedAt  *time.Time         `bson:"deleted_at,omitempty"`
	TOTPSecret string             `bson:"totp_secret"`
}

type TempUser struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	Username   string             `bson:"username"`
	Email      string             `bson:"email"`
	Password   string             `bson:"password"`
	CreatedAt  time.Time          `bson:"created_at"`
	ExpiredAt  time.Time          `bson:"expired_at"`
	SecretCode string             `bson:"secret_code"`
}

// ActivityLog model with BSON tags for MongoDB
type ActivityLog struct {
	ID            primitive.ObjectID `bson:"_id,omitempty"`
	Username      string             `bson:"username"`
	Token         string             `bson:"token"`
	ClientIP      string             `bson:"client_ip"`
	IsBlocked     bool               `bson:"is_blocked"`
	UserAgent     string             `bson:"user_agent"`
	CreatedAt     time.Time          `bson:"created_at"`
	ExpiresAt     time.Time          `bson:"expires_at"`
	DeletedAt     *time.Time         `bson:"deleted_at,omitempty"`
	ApproveMethod string             `bson:"approve_method,omitempty"`
	UserWebsiteID string             `bson:"user_website_id,omitempty"`
	RedirectUrl   string             `bson:"redirect_url,omitempty"`
}

type ThirdPartyLoginRequest struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Username    string             `bson:"username"`
	ClientID    int64              `bson:"client_id"`
	RedirectUrl string             `bson:"redirect_url"`
	CreatedAt   time.Time          `bson:"created_at"`
	ExpiresAt   time.Time          `bson:"expires_at"`
}
