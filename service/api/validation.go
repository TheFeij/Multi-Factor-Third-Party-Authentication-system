package api

import (
	"Third-Party-Multi-Factor-Authentication-System/service/db"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"net/mail"
	"regexp"
	"strings"
)

func ValidateOnSignup(store *db.Store, req *SignupRequest) error {
	if err := ValidateUsername(req.Username); err != nil {
		return err
	}

	if err := ValidatePassword(req.Password); err != nil {
		return err
	}

	if err := ValidateEmail(req.Email); err != nil {
		return err
	}

	_, err := store.GetUserByUsername(req.Username)
	if err == nil {
		return ErrUsernameAlreadyExists
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return err
	}

	_, err = store.GetUserByEmail(req.Email)
	if err == nil {
		return ErrEmailAlreadyExists
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return err
	}

	return nil
}

func ValidateOnLogin(store *db.Store, req *LoginRequest) error {
	if req.Username == "" && req.Email == "" {
		return errors.New("username or email must be entered")
	}

	if strings.TrimSpace(req.Username) != "" {
		if err := ValidateUsername(req.Username); err != nil {
			return err
		}
	}
	if strings.TrimSpace(req.Email) != "" {
		if err := ValidateEmail(req.Email); err != nil {
			return err
		}
	}

	if err := ValidatePassword(req.Password); err != nil {
		return err
	}

	// Validate the authorization request
	if req.ClientID == "" || req.RedirectUri == "" {
		return fmt.Errorf("invalid request")
	}

	return nil
}

func ValidateUsername(username string) error {
	if len(username) < 4 {
		return ErrUsernameTooShort
	}
	if len(username) > 64 {
		return ErrUsernameTooLong
	}

	if match, _ := regexp.MatchString("^[a-zA-Z]", username); !match {
		return ErrUsernameMustStartWithAlphabet
	}

	if match, _ := regexp.MatchString("^[a-zA-Z0-9ـ]*$", username); !match {
		return ErrUsernameInvalidCharacters
	}

	return nil
}

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}
	if len(password) > 64 {
		return ErrPasswordTooLong
	}

	if match, _ := regexp.MatchString("^[a-zA-Z0-9_!@#$%&*^.]*$", password); !match {
		return ErrPasswordInvalidCharacters
	}
	if match, _ := regexp.MatchString("^.*[a-z].*$", password); !match {
		return ErrPasswordMustContainLowercase
	}
	if match, _ := regexp.MatchString("^.*[A-Z].*$", password); !match {
		return ErrPasswordMustContainUppercase
	}
	if match, _ := regexp.MatchString("^.*[0-9].*$", password); !match {
		return ErrPasswordMustContainDigit
	}
	if match, _ := regexp.MatchString("^.*[_!@#$%&*^.].*$", password); !match {
		return ErrPasswordMustContainSpecialChar
	}

	return nil
}

func ValidateEmail(email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return ErrInvalidEmailFormat
	}

	return nil
}
