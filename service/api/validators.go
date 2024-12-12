package api

import (
	"Third-Party-Multi-Factor-Authentication-System/service/util"
	"github.com/go-playground/validator/v10"
)

var ValidUsername validator.Func = func(fl validator.FieldLevel) bool {
	if username, ok := fl.Field().Interface().(string); ok {
		if err := util.ValidateUsername(username); err != nil {
			return false
		}
		return true
	}
	return false
}

var ValidPassword validator.Func = func(fl validator.FieldLevel) bool {
	if password, ok := fl.Field().Interface().(string); ok {
		if err := util.ValidatePassword(password); err != nil {
			return false
		}
		return true
	}
	return false
}

var ValidFullname validator.Func = func(fl validator.FieldLevel) bool {
	if fullname, ok := fl.Field().Interface().(string); ok {
		if err := util.ValidateFullname(fullname); err != nil {
			return false
		}
		return true
	}
	return false
}

var ValidEmail validator.Func = func(fl validator.FieldLevel) bool {
	if email, ok := fl.Field().Interface().(string); ok {
		if err := util.ValidateEmail(email); err != nil {
			return false
		}
		return true
	}
	return false
}
