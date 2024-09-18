package db

import (
	"database/sql"
	"time"
)

type User struct {
	ID        int64
	Username  string
	Firstname string
	Lastname  string
	Email     string
	Password  string
	BirthDate time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt sql.NullTime
}

type ActivityLog struct {
	ID        int64
	UserID    int64
	Activity  string
	CreatedAt time.Time
	IPAddress sql.NullString
}
