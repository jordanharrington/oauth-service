package handler

import (
	"github.com/jordanharrington/jivium/internal/data"
	_default2 "github.com/jordanharrington/jivium/internal/handler/default"
	"github.com/jordanharrington/jivium/internal/storage"
	"github.com/jordanharrington/jivium/internal/token"
	"net/http"
)

type KeyHandler interface {
	PublicKey(w http.ResponseWriter, r *http.Request)
}

type ValidationHandler interface {
	Validate(w http.ResponseWriter, r *http.Request)
}

type RegistrationHandler interface {
	Register(w http.ResponseWriter, r *http.Request)
}

type AuthenticationHandler interface {
	Login(w http.ResponseWriter, r *http.Request)
	Refresh(w http.ResponseWriter, r *http.Request)
}

type OAuthHandler struct {
	AuthenticationHandler
	RegistrationHandler
	ValidationHandler
	KeyHandler
}

func Init(storage *storage.Storage, keyPath string) (*OAuthHandler, error) {
	tokenVendor, err := token.NewVendor(keyPath)
	if err != nil {
		return nil, err
	}

	db := data.NewDBClient(storage)

	return &OAuthHandler{
		AuthenticationHandler: _default2.NewDefaultAuthHandler(tokenVendor, db),
		RegistrationHandler:   _default2.NewDefaultRegistrationHandler(tokenVendor, db),
		ValidationHandler:     _default2.NewDefaultValidationHandler(tokenVendor),
		KeyHandler:            _default2.NewDefaultPublicKeyHandler(keyPath),
	}, nil
}
