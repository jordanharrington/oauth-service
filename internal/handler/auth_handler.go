package handler

import (
	"encoding/json"
	"github.com/jordanharrington/oauth-service/internal/model"
	"github.com/jordanharrington/oauth-service/internal/service"
	"log"
	"net/http"
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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	authResponse, err := h.authService.Login(req.Username, req.Password)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(authResponse); err != nil {
		log.Println("Error encoding login response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Logout handles user logout
func (h *authHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.LogoutRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	err := h.authService.InvalidateRefreshToken(req.RefreshToken)
	if err != nil {
		http.Error(w, "Failed to log out", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(`{"message": "Logged out successfully"}`))
	if err != nil {
		log.Println("Error encoding logout response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Register handles user registration
func (h *authHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	authResponse, err := h.authService.CreateUser(req.Username, req.Email, req.Password)
	if err != nil {
		http.Error(w, "Registration failed", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(authResponse); err != nil {
		log.Println("Error encoding registration response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Unregister handles user account deletion
func (h *authHandler) Unregister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.UnregisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	user, err := h.authService.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = h.authService.DeleteUser(user.ID)
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(`{"message": "User unregistered successfully"}`))
	if err != nil {
		log.Println("Error encoding unregister response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Refresh handles token refresh
func (h *authHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.RefreshRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	tokenResponse, err := h.authService.RenewTokens(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
		log.Println("Error encoding refresh response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Validate handles token validation
func (h *authHandler) Validate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.ValidateRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	isValid, err := h.authService.ValidateAccessToken(req.Token)
	if err != nil || !isValid {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	response := model.ValidateResponse{Valid: isValid}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("Error encoding validation response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// PublicKey handles retrieving the public key for token validation
func (h *authHandler) PublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	publicKey, err := h.authService.PublicKey()
	if err != nil {
		http.Error(w, "Failed to retrieve public key", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := model.PublicKeyResponse{PublicKey: publicKey}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("Error encoding public key response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
