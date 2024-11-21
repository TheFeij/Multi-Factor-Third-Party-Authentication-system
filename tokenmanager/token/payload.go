package token

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Payload struct {
	ID        primitive.ObjectID `json:"id"`
	Username  string             `json:"username"`
	IssuedAt  time.Time          `json:"issued_at"`
	ExpiredAt time.Time          `json:"expired_at"`
}

func NewPayload(username string, duration time.Duration) (*Payload, error) {
	return &Payload{
		ID:        primitive.NewObjectID(),
		Username:  username,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}, nil
}

func (p *Payload) Valid() error {
	if time.Now().After(p.ExpiredAt) {
		return ErrExpiredToken
	}
	return nil
}
