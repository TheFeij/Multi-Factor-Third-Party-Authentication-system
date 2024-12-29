package db

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"` // MongoDB will automatically generate an ObjectID
	Username string             `bson:"username"`
	Email    string             `bson:"email"`
}
