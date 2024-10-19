package db

import (
	"Third-Party-Multi-Factor-Authentication-System/config"
	"Third-Party-Multi-Factor-Authentication-System/util"
	"context"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type Store struct {
	client  *mongo.Client
	configs *config.Config
}

func NewStore(configs *config.Config) (*Store, error) {
	client, err := mongo.NewClient(options.Client().ApplyURI(configs.DatabaseSource))
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

	return &Store{client: client, configs: configs}, nil
}

func (s *Store) InsertUser(user *User) error {
	// Get the users collection from the database
	collection := s.client.Database(s.configs.DatabaseName).Collection("users")

	// Set CreatedAt and UpdatedAt fields before insertion
	now := time.Now().UTC()
	user.CreatedAt = now
	user.UpdatedAt = now
	user.DeletedAt = nil // Initial value is nil for DeletedAt

	// Insert the user document
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.InsertOne(ctx, user)
	if err != nil {
		return err
	}

	user.ID = result.InsertedID.(primitive.ObjectID)

	fmt.Println("User inserted successfully")
	return nil
}

func (s *Store) GetUser(id primitive.ObjectID) (*User, error) {
	// Get the users collection from the database
	collection := s.client.Database(s.configs.DatabaseName).Collection("users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Variable to store the result
	var user User

	// Perform the query with FindOne
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	if err != nil {
		// Return an error if the user is not found or another error occurs
		return nil, err
	}

	// Return the found user
	return &user, nil
}

func (s *Store) GetUserByUsernameAndPassword(username, password string) (*User, error) {
	// Get the users collection from the database
	collection := s.client.Database(s.configs.DatabaseName).Collection("users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Variable to store the result
	var user *User

	// Find the user by username
	err := collection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	// Compare the provided password with the stored hashed password
	err = util.CheckPassword(password, user.Password)
	if err != nil {
		return nil, errors.New("invalid password")
	}

	// Return the found user
	return user, nil
}

func (s *Store) GetUserByEmailAndPassword(email, password string) (*User, error) {
	// Get the users collection from the database
	collection := s.client.Database(s.configs.DatabaseName).Collection("users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Variable to store the result
	var user User

	// Find the user by email
	err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	// Compare the provided password with the stored hashed password
	err = util.CheckPassword(password, user.Password)
	if err != nil {
		return nil, errors.New("invalid password")
	}

	// Return the found user
	return &user, nil
}

func (s *Store) InsertActivityLog(log *ActivityLog) error {
	// Get the activity_logs collection from the database
	collection := s.client.Database(s.configs.DatabaseName).Collection("activity_logs")

	// Set CreatedAt and UpdatedAt fields before insertion
	now := time.Now().UTC()
	log.CreatedAt = now

	// Insert the log document
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.InsertOne(ctx, log)
	if err != nil {
		return err
	}

	log.ID = result.InsertedID.(primitive.ObjectID)

	fmt.Println("Activity log inserted successfully")
	return nil
}

func (s *Store) InsertSession(session *Session) error {
	// Get the sessions collection from the database
	collection := s.client.Database(s.configs.DatabaseName).Collection("sessions")

	// Set CreatedAt and UpdatedAt fields before insertion
	now := time.Now().UTC()
	session.CreatedAt = now
	session.DeletedAt = nil // Initial value is nil for DeletedAt

	// Insert the session document
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.InsertOne(ctx, session)
	if err != nil {
		return err
	}

	// Retrieve the inserted ID and update the session ID with it
	session.ID = result.InsertedID.(primitive.ObjectID) // Convert the inserted ID to ObjectID

	fmt.Println("Session inserted successfully with ID:", session.ID)
	return nil
}

func (s *Store) Disconnect() {
	s.client.Disconnect(context.TODO())
}
