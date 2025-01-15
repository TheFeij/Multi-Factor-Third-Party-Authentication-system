package db

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type LogType string

const (
	AndroidAppLoginFirstStep  LogType = "Android App Login First Step"
	AndroidAppLoginSecondStep LogType = "Android App Login Second Step"

	AndroidAppSignupFirstStep  LogType = "Android App Signup First Step"
	AndroidAppSignupSecondStep LogType = "Android App Signup Second Step"

	LoginFirstStep            LogType = "Login First Step"
	LoginSecondStepTOTP       LogType = "Login Second Step With TOTP"
	LoginSecondStepAppApprove LogType = "Login Second Step With Application Approve"
)

type Order int8

const (
	Ascending  Order = 1
	Descending Order = -1
)

type ApproveMethod string

const (
	TOTP       = "totp"
	AppApprove = "app approve"
	Email      = "email"
)

type Log struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Type     LogType            `bson:"type"`
	Username string             `bson:"username"`
	Token    string             `bson:"token,omitempty"`

	DeviceInfo      string        `bson:"device_info"`
	IP              string        `bson:"ip"`
	Approved        bool          `bson:"approved,omitempty"`
	ApproveMethod   ApproveMethod `bson:"approve_method,omitempty"`
	ClientWebsiteID string        `bson:"client_website_id,omitempty"`
	RedirectUrl     string        `bson:"redirect_url,omitempty"`

	CreatedAt time.Time `bson:"created_at"`
	ExpiresAt time.Time `bson:"expires_at,omitempty"`
}

func (s *Store) InsertLog(l *Log) error {
	collection := s.Client.Database(s.configs.DatabaseName).Collection("logs")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	l.CreatedAt = time.Now().UTC()

	result, err := collection.InsertOne(ctx, l)
	if err != nil {
		return err
	}

	l.ID = result.InsertedID.(primitive.ObjectID)

	return nil
}

func (s *Store) GetLogs(filters bson.D, order bson.D, pageSize, page int64) ([]Log, error) {
	collection := s.Client.Database(s.configs.DatabaseName).Collection("logs")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	skip := (page - 1) * pageSize

	opts := options.Find().
		SetSort(order).
		SetLimit(pageSize).
		SetSkip(skip)

	cursor, err := collection.Find(ctx, filters, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var logs []Log
	if err = cursor.All(ctx, &logs); err != nil {
		return nil, err
	}

	return logs, nil
}
