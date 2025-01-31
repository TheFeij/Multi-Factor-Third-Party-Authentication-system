package db

import (
	"context"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"mobile-app-server/config"
	"mobile-app-server/util"
	"time"
)

type Store struct {
	Client  *mongo.Client
	configs *config.Config
}

func NewStore(configs *config.Config) (*Store, error) {
	client, err := mongo.NewClient(options.Client().ApplyURI(configs.DatabaseSource))
	if err != nil {
		return nil, err
	}

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

	log.Info().Msg("Connected to mongoDB successfully")

	return &Store{Client: client, configs: configs}, nil
}

func (s *Store) InsertUserWithSession(sessCtx mongo.SessionContext, user *User) error {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

	// Set CreatedAt and UpdatedAt fields before insertion
	now := time.Now().UTC()
	user.CreatedAt = now
	user.UpdatedAt = now
	user.DeletedAt = nil // Initial value is nil for DeletedAt

	// Insert the user document
	result, err := collection.InsertOne(sessCtx, user)
	if err != nil {
		return err
	}

	// Set the inserted ID back to the user
	user.ID = result.InsertedID.(primitive.ObjectID)

	log.Info().Msg(fmt.Sprintf("user inserted to the database: %v", user))
	return nil
}

func (s *Store) InsertTempUserWithSession(sessCtx mongo.SessionContext, tempUser *TempUser) error {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("temp_users")

	// Set CreatedAt and UpdatedAt fields before insertion
	now := time.Now().UTC()
	tempUser.CreatedAt = now

	// Insert the user document
	result, err := collection.InsertOne(sessCtx, tempUser)
	if err != nil {
		return err
	}

	// Set the inserted ID back to the user
	tempUser.ID = result.InsertedID.(primitive.ObjectID)

	log.Info().Msg(fmt.Sprintf("temp user inserted to the database: %v", tempUser))
	return nil
}

func (s *Store) DeleteTempUserWithSession(sessCtx mongo.SessionContext, id primitive.ObjectID) error {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("temp_users")

	// Perform the deletion
	result, err := collection.DeleteOne(sessCtx, bson.M{"_id": id})
	if err != nil {
		return err // Return the error if the operation fails
	}

	// Check if a user was actually deleted
	if result.DeletedCount == 0 {
		return fmt.Errorf("no user found with id: %s", id.Hex())
	}

	return nil // Return nil to indicate success
}

func (s *Store) GetTempUser(id primitive.ObjectID) (*TempUser, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("temp_users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Variable to store the result
	var tempUser TempUser

	// Perform the query with FindOne
	err := collection.FindOne(ctx, bson.M{"_id": id}).Decode(&tempUser)
	if err != nil {
		// Return an error if the user is not found or another error occurs
		return nil, err
	}

	// Return the found user
	return &tempUser, nil
}

func (s *Store) GetTempUserWithSession(sessCtx mongo.SessionContext, id primitive.ObjectID) (*TempUser, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("temp_users")

	// Variable to store the result
	var tempUser TempUser

	// Perform the query with FindOne
	err := collection.FindOne(sessCtx, bson.M{"_id": id}).Decode(&tempUser)
	if err != nil {
		// Return an error if the user is not found or another error occurs
		return nil, err
	}

	// Return the found user
	return &tempUser, nil
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Variable to store the result
	var user User

	// Perform the query with FindOne
	err := collection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		// Return an error if the user is not found or another error occurs
		return nil, err
	}

	// Return the found user
	return &user, nil
}

func (s *Store) GetUserByUsernameAndPassword(username, password string) (*User, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

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
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

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

func (s *Store) GetUserByEmail(email string) (*User, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Variable to store the result
	var user User

	// Find the user by email
	err := collection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		return nil, err
	}

	// Return the found user
	return &user, nil
}

func (s *Store) Disconnect() {
	s.Client.Disconnect(context.TODO())
}

func (s *Store) Transaction(ctx context.Context, callback func(sessCtx mongo.SessionContext) (interface{}, error)) error {
	// Start a MongoDB session for the transaction
	session, err := s.Client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)

	_, err = session.WithTransaction(ctx, callback)
	if err != nil {
		return err
	}

	return nil
}
