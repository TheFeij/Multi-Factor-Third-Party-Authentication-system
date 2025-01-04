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

func (s *Store) InsertTempUser(tempUser *TempUser) error {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("temp_users")

	// Set CreatedAt and UpdatedAt fields before insertion
	now := time.Now().UTC()
	tempUser.CreatedAt = now
	tempUser.ExpiredAt = now.Add(24 * time.Hour)

	// Insert the user document
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.InsertOne(ctx, tempUser)
	if err != nil {
		return err
	}

	tempUser.ID = result.InsertedID.(primitive.ObjectID)

	fmt.Println("Temp User inserted successfully")
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

func (s *Store) DeleteTempUser(id primitive.ObjectID) error {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("temp_users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Perform the deletion
	result, err := collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return err // Return the error if the operation fails
	}

	// Check if a user was actually deleted
	if result.DeletedCount == 0 {
		return fmt.Errorf("no user found with id: %s", id.Hex())
	}

	return nil // Return nil to indicate success
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

func (s *Store) UpdateUser(user *User) error {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ensure that either username or email is provided
	if user.Username == "" && user.Email == "" {
		return fmt.Errorf("username or email must be provided for update")
	}

	// Query to find user by username or email
	filter := bson.M{
		"$or": []bson.M{
			{"username": user.Username},
			{"email": user.Email},
		},
	}

	// Prepare the update document
	update := bson.M{
		"$set": bson.M{
			"password":   user.Password,
			"updated_at": time.Now(),
			// Add additional fields to update as needed
		},
	}

	// Perform the update operation
	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		// Return an error if the update fails
		return err
	}

	// If no documents were modified, return an error
	if result.MatchedCount == 0 {
		return fmt.Errorf("no user found with username '%s' or email '%s'", user.Username, user.Email)
	}

	// Retrieve the updated user document
	var updatedUser User
	err = collection.FindOne(ctx, filter).Decode(&updatedUser)
	if err != nil {
		// Return an error if unable to fetch the updated document
		return err
	}

	// Return the updated user
	return nil
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

func (s *Store) InsertThirdPartyLoginRequests(sessCtx mongo.SessionContext, req *ThirdPartyLoginRequests) error {
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

func (s *Store) RemoveThirdPartyLoginRequest(sessCtx mongo.SessionContext, username string, clientID int64) error {
	// Get the third_party_login_requests collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("third_party_login_requests")

	// Create the filter to match the username and clientID
	filter := bson.D{
		{"username", username},
		{"client_id", clientID},
	}

	// Perform the delete operation
	_, err := collection.DeleteMany(sessCtx, filter)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) GetThirdPartyLoginRequests(username string, clientID int64) (*ThirdPartyLoginRequests, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("third_party_login_requests")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Variable to store the result
	var req ThirdPartyLoginRequests

	// Find the user by email
	err := collection.FindOne(ctx, bson.M{"username": username, "client_id": clientID}).Decode(&req)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}

	// Return the found user
	return &req, nil
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

func (s *Store) InsertSessionWithSession(sessCtx mongo.SessionContext, session *Session) error {
	// Get the sessions collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("sessions")

	// Set CreatedAt and UpdatedAt fields before insertion
	now := time.Now().UTC()
	session.CreatedAt = now
	session.DeletedAt = nil // Initial value is nil for DeletedAt

	result, err := collection.InsertOne(sessCtx, session)
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
