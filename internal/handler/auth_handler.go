package handler

import (
	"encoding/json"
	"github.com/jordanharrington/oauth-service/internal/logger"
	"github.com/jordanharrington/oauth-service/internal/model"
	"github.com/jordanharrington/oauth-service/internal/service"
	"net/http"
)

const (
	ContentTypeHeader        = "Content-Type"
	ContentTypeJSON          = "application/json"
	ErrorMethodNotAllowed    = "Method not allowed"
	ErrorInvalidContentType  = "Invalid content type"
	ErrorInvalidPayload      = "Invalid request payload"
	ErrorInternalServer      = "Internal server error"
	ErrorInvalidToken        = "Invalid token"
	MessageLogoutSuccess     = `{"message": "Logged out successfully"}`
	MessageUnregisterSuccess = `{"message": "User unregistered successfully"}`
)

// AuthHandler defines the interface for all auth-related handlers
type AuthHandler interface {
	Login(w http.ResponseWriter, r *http.Request)
	Logout(w http.ResponseWriter, r *http.Request)
	Register(w http.ResponseWriter, r *http.Request)
	Unregister(w http.ResponseWriter, r *http.Request)
	Refresh(w http.ResponseWriter, r *http.Request)
	Validate(w http.ResponseWriter, r *http.Request)
	PublicKey(w http.ResponseWriter, r *http.Request)
}

// authHandler struct implements the AuthHandler interface
type authHandler struct {
	authService service.AuthService
}

// NewAuthHandler returns a new instance of AuthHandler
func NewAuthHandler(authService service.AuthService) AuthHandler {
	return &authHandler{
		authService: authService,
	}
}

// Login handles user login
func (h *authHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, ErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get(ContentTypeHeader) != ContentTypeJSON {
		http.Error(w, ErrorInvalidContentType, http.StatusUnsupportedMediaType)
		return
	}

	var req model.LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrorInvalidPayload, http.StatusBadRequest)
		return
	}

	authResponse, err := h.authService.Login(req.Username, req.Password)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(ContentTypeHeader, ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(authResponse); err != nil {
		logger.Log().Error().Msgf("Error encoding login response: %v", err)
		http.Error(w, ErrorInternalServer, http.StatusInternalServerError)
	}
}

// Logout handles user logout
func (h *authHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, ErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get(ContentTypeHeader) != ContentTypeJSON {
		http.Error(w, ErrorInvalidContentType, http.StatusUnsupportedMediaType)
		return
	}

	var req model.LogoutRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrorInvalidPayload, http.StatusBadRequest)
		return
	}

	err := h.authService.InvalidateRefreshToken(req.RefreshToken)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(MessageLogoutSuccess))
	if err != nil {
		logger.Log().Error().Msgf("Error encoding lougout response: %v", err)
		http.Error(w, ErrorInternalServer, http.StatusInternalServerError)
	}
}

// Register handles user registration
func (h *authHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, ErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get(ContentTypeHeader) != ContentTypeJSON {
		http.Error(w, ErrorInvalidContentType, http.StatusUnsupportedMediaType)
		return
	}

	var req model.RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrorInvalidPayload, http.StatusBadRequest)
		return
	}

	authResponse, err := h.authService.CreateUser(req.Username, req.Email, req.Password)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(ContentTypeHeader, ContentTypeJSON)
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(authResponse); err != nil {
		logger.Log().Error().Msgf("Error encoding registration response: %v", err)
		http.Error(w, ErrorInternalServer, http.StatusInternalServerError)
	}
}

// Unregister handles user account deletion
func (h *authHandler) Unregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, ErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get(ContentTypeHeader) != ContentTypeJSON {
		http.Error(w, ErrorInvalidContentType, http.StatusUnsupportedMediaType)
		return
	}

	var req model.UnregisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrorInvalidPayload, http.StatusBadRequest)
		return
	}

	user, err := h.authService.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	err = h.authService.DeleteUser(user.ID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(MessageUnregisterSuccess))
	if err != nil {
		logger.Log().Error().Msgf("Error encoding unregister response: %v", err)
		http.Error(w, ErrorInternalServer, http.StatusInternalServerError)
	}
}

// Refresh handles token refresh
func (h *authHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, ErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get(ContentTypeHeader) != ContentTypeJSON {
		http.Error(w, ErrorInvalidContentType, http.StatusUnsupportedMediaType)
		return
	}

	var req model.RefreshRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrorInvalidPayload, http.StatusBadRequest)
		return
	}

	tokenResponse, err := h.authService.RenewTokens(req.RefreshToken)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(ContentTypeHeader, ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
		logger.Log().Error().Msgf("Error encoding refresh response: %v", err)
		http.Error(w, ErrorInternalServer, http.StatusInternalServerError)
	}
}

// Validate handles token validation
func (h *authHandler) Validate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, ErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get(ContentTypeHeader) != ContentTypeJSON {
		http.Error(w, ErrorInvalidContentType, http.StatusUnsupportedMediaType)
		return
	}

	var req model.ValidateRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrorInvalidPayload, http.StatusBadRequest)
		return
	}

	isValid, err := h.authService.ValidateAccessToken(req.Token)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	if !isValid {
		http.Error(w, ErrorInvalidToken, http.StatusUnauthorized)
		return
	}

	response := model.ValidateResponse{Valid: isValid}
	w.Header().Set(ContentTypeHeader, ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Log().Error().Msgf("Error encoding validate response: %v", err)
		http.Error(w, ErrorInternalServer, http.StatusInternalServerError)
	}
}

// PublicKey handles retrieving the public key for token validation
func (h *authHandler) PublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, ErrorMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get(ContentTypeHeader) != ContentTypeJSON {
		http.Error(w, ErrorInvalidContentType, http.StatusUnsupportedMediaType)
		return
	}

	publicKey, err := h.authService.PublicKey()
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set(ContentTypeHeader, ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	response := model.PublicKeyResponse{PublicKey: publicKey}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Log().Error().Msgf("Error encoding public key response: %v", err)
		http.Error(w, ErrorInternalServer, http.StatusInternalServerError)
	}
}

func (h *authHandler) handleServiceError(w http.ResponseWriter, err error) {
	var msg string

	if model.IsRequestError(err) {
		msg = "client error: %v"
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else if model.IsServiceError(err) {
		msg = "sever error: %v"
		http.Error(w, ErrorInternalServer, http.StatusInternalServerError)
	} else {
		msg = "unknown error: %v"
		http.Error(w, "Unknown error", http.StatusInternalServerError)
	}

	logger.Log().Error().Msgf(msg, err)
}
