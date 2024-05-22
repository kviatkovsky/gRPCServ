package storage

import "errors"

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserNotAdmin      = errors.New("user is not admin")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrAppNotFound       = errors.New("app not found")
)
