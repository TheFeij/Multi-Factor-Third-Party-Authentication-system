package db

import (
	"admin-server/config"
	"admin-server/util"
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

func (s *Store) GetAdminByUsernameAndPassword(username, password string) (Admin, error) {
	collection := s.Client.Database(s.configs.DatabaseName).Collection("admins")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var admin Admin

	err := collection.FindOne(ctx, bson.M{"username": username}).Decode(&admin)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return Admin{}, errors.New("user not found")
		}
		return Admin{}, err
	}

	err = util.CheckPassword(password, admin.Password)
	if err != nil {
		return Admin{}, errors.New("invalid password")
	}

	return admin, nil
}

func (s *Store) GetUsers(page, pageSize int64) ([]User, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Calculate the skip value (for pagination)
	skip := (page - 1) * pageSize

	// Perform the query with Find and limit the results based on page size
	cursor, err := collection.Find(ctx, bson.M{}, options.Find().SetSkip(skip).SetLimit(pageSize))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	// Slice to store the result users
	var users []User
	for cursor.Next(ctx) {
		var user User
		if err := cursor.Decode(&user); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	// Check if an error occurred during iteration
	if err := cursor.Err(); err != nil {
		return nil, err
	}

	// Return the list of users
	return users, nil
}

func (s *Store) DeleteUser(id primitive.ObjectID) error {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

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

	return nil
}

func (s *Store) UpdateUser(updatedUser *User) (*User, error) {
	// Get the users collection from the database
	collection := s.Client.Database(s.configs.DatabaseName).Collection("users")

	// Context for the query
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Prepare the update data, using the fields of the User struct
	updateData := bson.M{}
	updateData["username"] = updatedUser.Username
	updateData["email"] = updatedUser.Email
	updateData["password"] = updatedUser.Password
	updateData["totpSecret"] = updatedUser.TOTPSecret
	updateData["created_at"] = updatedUser.CreatedAt
	updateData["updated_at"] = updatedUser.UpdatedAt

	// Perform the update
	result := collection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": updatedUser.ID}, // Filter by user ID
		bson.M{
			"$set": updateData, // Update the fields in the updateData map
		},
		options.FindOneAndUpdate().SetReturnDocument(options.After), // Return the updated document
	)

	// Check if the user was found and updated
	if result.Err() != nil {
		if errors.Is(result.Err(), mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("no user found with id: %s", updatedUser.ID.Hex())
		}
		return nil, result.Err()
	}

	// Declare a variable to store the updated user
	var finalUser User
	if err := result.Decode(&finalUser); err != nil {
		return nil, err
	}

	// Return the updated user
	return &finalUser, nil
}

func (s *Store) Disconnect() {
	s.Client.Disconnect(context.TODO())
}
