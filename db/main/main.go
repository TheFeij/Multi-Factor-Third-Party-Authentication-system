package main

import (
	"Third-Party-Multi-Factor-Authentication-System/db"
	"fmt"
	"time"
)

func main() {
	s, err := db.NewStore()
	if err != nil {
		panic(err)
	}
	defer s.Disconnect()

	user := db.User{
		Username:  "john_doe",
		Firstname: "John",
		Lastname:  "Doe",
		Email:     "john@example.com",
		Password:  "securepassword",
		BirthDate: time.Now(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Insert a new user
	err = s.InsertUser(user)
	if err != nil {
		fmt.Println("Error inserting user:", err)
	}

	activityLog := db.ActivityLog{
		UserID:    user.ID,
		Activity:  "Logged In",
		CreatedAt: time.Now(),
	}

	// Insert an activity log
	err = s.InsertActivityLog(activityLog)
	if err != nil {
		fmt.Println("Error inserting activity log:", err)
	}
}
