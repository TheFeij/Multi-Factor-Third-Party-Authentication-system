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

type ThirdPartyLoginRequest struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Username    string             `bson:"username"`
	ClientID    int64              `bson:"client_id"`
	RedirectUrl string             `bson:"redirect_url"`
	CreatedAt   time.Time          `bson:"created_at"`
	ExpiresAt   time.Time          `bson:"expires_at"`
}
