package db

import (
	"authentication-server/service/config"
	"authentication-server/service/util"
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

func (s *Store) GetUserWithSession(sessCtx mongo.SessionContext, id primitive.ObjectID) (*User, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

	// Variable to store the result
	var user User

	// Perform the query with FindOne
	err := collection.FindOne(sessCtx, bson.M{"_id": id}).Decode(&user)
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

func (s *Store) InsertThirdPartyLoginRequest(sessCtx mongo.SessionContext, req *ThirdPartyLoginRequest) error {
	// Get the activity_logs collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("third_party_login_requests")

	// Set CreatedAt and UpdatedAt fields before insertion
	now := time.Now().UTC()
	req.CreatedAt = now

	result, err := collection.InsertOne(sessCtx, req)
	if err != nil {
		return err
	}

	req.ID = result.InsertedID.(primitive.ObjectID)

	fmt.Println("third party login request inserted successfully")
	return nil
}

func (s *Store) GetThirdPartyLoginRequestWithSession(sessCtx mongo.SessionContext, username string, clientID int64) (*ThirdPartyLoginRequest, error) {
	// Get the third_party_login_requests collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("third_party_login_requests")

	// Create a variable to hold the result
	var lastRequest ThirdPartyLoginRequest

	filter := bson.D{{"username", username}, {"client_id", clientID}}

	opts := options.FindOne().SetSort(bson.D{{"created_at", -1}})

	err := collection.FindOne(sessCtx, filter, opts).Decode(&lastRequest)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			fmt.Println("No login requests found for the user")
			return nil, nil
		}
		return nil, err
	}

	fmt.Println("Last login request for user retrieved successfully")
	return &lastRequest, nil
}

func (s *Store) GetThirdPartyLoginRequest(username string, clientID int64) (*ThirdPartyLoginRequest, error) {
	// Get the third_party_login_requests collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("third_party_login_requests")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a variable to hold the result
	var lastRequest ThirdPartyLoginRequest

	filter := bson.D{{"username", username}, {"client_id", clientID}}

	opts := options.FindOne().SetSort(bson.D{{"created_at", -1}})

	err := collection.FindOne(ctx, filter, opts).Decode(&lastRequest)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			fmt.Println("No login requests found for the user")
			return nil, nil
		}
		return nil, err
	}

	fmt.Println("Last login request for user retrieved successfully")
	return &lastRequest, nil
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
