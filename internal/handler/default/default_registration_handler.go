package _default

import (
	"encoding/json"
	"github.com/jordanharrington/jivium/internal/data"
	"github.com/jordanharrington/jivium/internal/token"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"time"
)

type UserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserResponse struct {
	ID        uint      `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type TokenResponse struct {
	User         UserResponse `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
}

type DefaultRegistrationHandler struct {
	vendor *token.Vendor
	db     *data.DBClient
}

func NewDefaultRegistrationHandler(vendor *token.Vendor, db *data.DBClient) *DefaultRegistrationHandler {
	return &DefaultRegistrationHandler{
		vendor: vendor,
		db:     db,
	}
}

func (d *DefaultRegistrationHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Parse the request body into the struct
	var req UserRequest

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Validate the input data
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.Password) == "" {
		http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	// Check if the username already exists
	existingUser, err := d.db.GetUserByUsername(req.Username)
	if err == nil && existingUser != nil {
		http.Error(w, "Username is already taken", http.StatusConflict)
		return
	}

	// Check if the email already exists
	existingUser, err = d.db.GetUserByEmail(req.Email)
	if err == nil && existingUser != nil {
		http.Error(w, "Email is already in use", http.StatusConflict)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create a new user instance
	newUser := data.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	// Save the new user to the database
	err = d.db.CreateUser(&newUser)
	if err != nil {
		log.Println("Error saving user:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate JWT (access token)
	accessToken, err := d.vendor.GenerateJWT(newUser.ID)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Generate a refresh token
	refreshToken, err := d.vendor.GenerateRefreshToken(&newUser) // 7 days validity
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Store refresh token in the database
	err = d.db.CreateToken(refreshToken)
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	// Build response using TokenResponse struct
	response := TokenResponse{
		User: UserResponse{
			ID:        newUser.ID,
			Username:  newUser.Username,
			Email:     newUser.Email,
			CreatedAt: newUser.CreatedAt,
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}
	// Respond with the created user and token
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Println("Error encoding response:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
