package apperrors

import (
	"errors"
	"net/http"
)

const (
	unauthorized = "unauthorized" // auth, refresh token; 401 not valid access_token
	badRequest   = "bad_request"  // Post data; 400 incorrect structure
	badGateway   = "bad_gateway"  // ; 502 foreign server error, e.g. database error
	conflict     = "conflict"     // Create, update; 409 already exists
	internal     = "internal"     // ; 500 server error, something was broken
	notFound     = "not_found"    // ; 404 not found
	forbidden    = "forbidden"    // ; 403 forbidden
)

type appError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *appError) Error() string {
	return e.Message
}

func (e *appError) Status() int {
	switch e.Code {
	case unauthorized:
		return http.StatusUnauthorized
	case badRequest:
		return http.StatusBadRequest
	case badGateway:
		return http.StatusBadGateway
	case conflict:
		return http.StatusConflict
	case internal:
		return http.StatusInternalServerError
	case notFound:
		return http.StatusNotFound
	case forbidden:
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

func HttpStatus(err error) int {
	var e *appError
	if errors.As(err, &e) {
		return e.Status()
	}
	return http.StatusInternalServerError
}

/*
* Error "Factories"
 */

// NewAuthorization to create a 401
func NewUnauthorized(reason string) *appError {
	return &appError{
		Code:    unauthorized,
		Message: reason,
	}
}

// NewBadRequest to create 400 errors (validation, for example)
func NewBadRequest(reason string) *appError {
	return &appError{
		Code:    badRequest,
		Message: reason,
	}
}

// NewBadGateway to create 502 errors (db errors, for example)
func NewBadGateway(reason string) *appError {
	return &appError{
		Code:    badGateway,
		Message: reason,
	}
}

// NewConflict to create an error for 409
func NewConflict(reason string) *appError {
	return &appError{
		Code:    conflict,
		Message: reason,
	}
}

// NewInternal for 500 errors and unknown errors
func NewInternal(reason string) *appError {
	return &appError{
		Code:    internal,
		Message: reason,
	}
}

// NewNotFound to create an error for 404
func NewNotFound(reason string) *appError {
	return &appError{
		Code:    notFound,
		Message: reason,
	}
}

// NewForbidden 403
func NewForbidden(reason string) *appError {
	return &appError{
		Code:    forbidden,
		Message: reason,
	}
}
