package db

import (
	"Third-Party-Multi-Factor-Authentication-System/service/config"
	"Third-Party-Multi-Factor-Authentication-System/service/util"
	"context"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

func (s *Store) InsertUser(user *User) error {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

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

func (s *Store) InsertVerifyEmail(verifyEmail *VerifyEmails) error {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("verify_email")

	// Set CreatedAt and UpdatedAt fields before insertion
	now := time.Now().UTC()
	verifyEmail.CreatedAt = now
	verifyEmail.ExpiredAt = now.Add(15 * time.Minute)
	verifyEmail.IsUsed = false

	// Insert the user document
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.InsertOne(ctx, verifyEmail)
	if err != nil {
		return err
	}

	verifyEmail.ID = result.InsertedID.(primitive.ObjectID)

	log.Info().Msg(fmt.Sprintf("verify email inserted to the database: %v", verifyEmail))
	return nil
}

func (s *Store) GetUser(id primitive.ObjectID) (*User, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

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

func (s *Store) InsertActivityLog(log *ActivityLog) error {
	// Get the activity_logs collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("activity_logs")

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
	collection := s.Client.Database(s.configs.DatabaseName).Collection("sessions")

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

	log.Info().Msg(fmt.Sprintf("session inserted to the database successfully: %v", session))
	return nil
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