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
	ID         primitive.ObjectID `bson:"_id,omitempty"` // MongoDB will automatically generate an ObjectID
	Username   string             `bson:"username"`
	Email      string             `bson:"email"`
	Password   string             `bson:"password"`
	CreatedAt  time.Time          `bson:"created_at"`
	ExpiredAt  time.Time          `bson:"expired_at"`
	SecretCode string             `bson:"secret_code"`
}

// ActivityLog model with BSON tags
type ActivityLog struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"` // MongoDB ObjectID
	UserID    primitive.ObjectID `bson:"user_id"`       // References User's ID
	Activity  string             `bson:"activity"`
	CreatedAt time.Time          `bson:"created_at"`
	IPAddress *string            `bson:"ip_address,omitempty"`
}

// Session model with BSON tags for MongoDB
type Session struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`        // MongoDB will handle UUID
	Username     string             `bson:"username"`             // Username for the session
	RefreshToken string             `bson:"refresh_token"`        // Token used to refresh the session
	UserAgent    string             `bson:"user_agent"`           // User agent info
	ClientIP     string             `bson:"client_ip"`            // IP address of the Client
	IsBlocked    bool               `bson:"is_blocked"`           // Indicates if the session is blocked
	CreatedAt    time.Time          `bson:"created_at"`           // Session creation time
	ExpiresAt    time.Time          `bson:"expires_at"`           // Expiration time for the session
	DeletedAt    *time.Time         `bson:"deleted_at,omitempty"` // Deleted time, if soft delete is used
}
