package errors

import "errors"

var (
	ErrFailedToPingDatabase = errors.New("failed to ping database")
	ErrInvalidDriver        = errors.New("unsupported database driver")
	ErrDuplicateKey         = errors.New("unique key already exists")
)
