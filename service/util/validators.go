package util

import (
	"fmt"
	"net/mail"
	"regexp"
)

func ValidateUsername(username string) error {
	if len(username) < 4 {
		return fmt.Errorf("username must be at least 4 characters")
	}
	if len(username) > 64 {
		return fmt.Errorf("username must be at most 64 characters")
	}

	if match, _ := regexp.MatchString("^[a-zA-Z][a-zA-Z0-9_]*$", username); !match {
		return fmt.Errorf("username must contain only alphabets, digits and underscore. and must start with an alphabet")
	}

	return nil
}

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 64 {
		return fmt.Errorf("password must be at most 64 characters")
	}

	if match, _ := regexp.MatchString("^[a-zA-Z0-9_!@#$%&*^.]*$", password); !match {
		return fmt.Errorf("invalid character in password; only alphabets, digits, and the following special characters are allowed: _!@#$%%&*.^")
	}
	if match, _ := regexp.MatchString("^.*[a-z].*$", password); !match {
		return fmt.Errorf("password must have at least one lowercase alphabet")
	}
	if match, _ := regexp.MatchString("^.*[A-Z].*$", password); !match {
		return fmt.Errorf("password must have at least one uppercase alphabet")
	}
	if match, _ := regexp.MatchString("^.*[0-9].*$", password); !match {
		return fmt.Errorf("password must have at least one digit")
	}
	if match, _ := regexp.MatchString("^.*[_!@#$%&*^.].*$", password); !match {
		return fmt.Errorf("password must have at least one of these special character: _!@#$%%&.*^")
	}

	return nil
}

func ValidateFullname(fullname string) error {
	if len(fullname) < 3 {
		return fmt.Errorf("fullname must be at least 3 characters")
	}
	if len(fullname) > 64 {
		return fmt.Errorf("fullname must be at most 64 characters")
	}

	if match, _ := regexp.MatchString("^[a-zA-Z]+([\\s][a-zA-Z]+)*$", fullname); !match {
		return fmt.Errorf("fullname must contain only alphabets and spaces")
	}

	return nil
}

func ValidateEmail(email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("invalid email address")
	}

	return nil
}
