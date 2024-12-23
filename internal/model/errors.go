package model

import (
	"errors"
	"fmt"
)

// RequestError represents an error caused by invalid client input
type RequestError struct {
	Message string
}

func (e *RequestError) Error() string {
	return e.Message
}

// ServiceError represents an internal server error
type ServiceError struct {
	Message string
}

func (e *ServiceError) Error() string {
	return e.Message
}

func NewRequestError(format string, args ...any) error {
	return &RequestError{Message: fmt.Sprintf(format, args...)}
}

func NewServiceError(format string, args ...any) error {
	return &ServiceError{Message: fmt.Sprintf(format, args...)}
}

func IsRequestError(err error) bool {
	var clientError *RequestError
	ok := errors.As(err, &clientError)
	return ok
}

func IsServiceError(err error) bool {
	var serverError *ServiceError
	ok := errors.As(err, &serverError)
	return ok
}
