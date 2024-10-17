package db

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type Store struct {
	client *mongo.Client
}

func NewStore() (*Store, error) {
	// Set MongoDB URI
	uri := "mongodb://localhost:27017" // Replace with your MongoDB URI
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	// Check the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, err
	}

	fmt.Println("Connected to MongoDB!")

	return &Store{client: client}, nil
}

func (s *Store) InsertUser(user User) error {
	// Get the users collection from the database
	collection := s.client.Database("your_database").Collection("users")

	// Insert the user document
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, user)
	if err != nil {
		return err
	}

	fmt.Println("User inserted successfully")
	return nil
}

func (s *Store) InsertActivityLog(log ActivityLog) error {
	// Get the activity_logs collection from the database
	collection := s.client.Database("your_database").Collection("activity_logs")

	// Insert the log document
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, log)
	if err != nil {
		return err
	}

	fmt.Println("Activity log inserted successfully")
	return nil
}

func (s *Store) Disconnect() {
	s.client.Disconnect(context.TODO())
}
