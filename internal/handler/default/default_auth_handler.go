package _default

import (
	"encoding/json"
	"github.com/jordanharrington/jivium/internal/data"
	"github.com/jordanharrington/jivium/internal/token"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenResponse struct {
	AccessToken string `json:"access_token"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type DefaultAuthHandler struct {
	vendor *token.Vendor
	db     *data.DBClient
}

func NewDefaultAuthHandler(vendor *token.Vendor, db *data.DBClient) *DefaultAuthHandler {
	return &DefaultAuthHandler{
		vendor: vendor,
		db:     db,
	}
}

func (d *DefaultAuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Retrieve user from the database
	user, err := d.db.GetUserByUsername(req.Username)
	if err != nil || user == nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Compare the provided password with the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate a JWT (access token)
	accessToken, err := d.vendor.GenerateJWT(user.ID)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Generate a refresh token
	refreshToken, err := d.vendor.GenerateRefreshToken(user)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Store refresh token in the database (or cache)
	err = d.db.CreateToken(refreshToken)
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	// Return both token as the response
	response := LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Println("Error encoding response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (d *DefaultAuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Verify refresh token
	claims, err := d.vendor.VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Extract user ID from claims
	userID := uint(claims[token.UserIdClaimKey].(float64))

	// Generate new JWT (access token)
	newAccessToken, err := d.vendor.GenerateJWT(userID)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Respond with the new access token
	w.Header().Set("Content-Type", "application/json")
	response := RefreshTokenResponse{
		AccessToken: newAccessToken,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("Error encoding response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
