package errors

import (
	"errors"
)

var (
	ErrImageToLarge        = errors.New("uploaded image exceeds the allowed size")
	ErrInvalidBase64String = errors.New("invlaid base64 string")
	ErrNoImageFound        = errors.New("no image found")
)
