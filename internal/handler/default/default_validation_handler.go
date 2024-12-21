package _default

import (
	"encoding/json"
	"fmt"
	"github.com/jordanharrington/jivium/internal/token"
	"net/http"
)

type ValidateRequest struct {
	Token string `json:"token"`
}

type ValidateResponse struct {
	Valid    bool   `json:"valid"`
	UserID   uint   `json:"user_id,omitempty"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Error    string `json:"error,omitempty"`
}

type DefaultValidationHandler struct {
	vendor *token.Vendor
}

func NewDefaultValidationHandler(vendor *token.Vendor) *DefaultValidationHandler {
	return &DefaultValidationHandler{
		vendor: vendor,
	}
}

func (d *DefaultValidationHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var req ValidateRequest
	// Parse the request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate the JWT token
	claims, err := d.vendor.VerifyJWT(req.Token)
	if err != nil {
		// Respond with a 401 status if token is invalid or expired
		response := ValidateResponse{
			Valid: false,
			Error: err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Extract user-related claims from the token
	userID, err := userIDToUint(claims.Subject)
	if err != nil {
		http.Error(w, "Invalid user", http.StatusBadRequest)
		return
	}
	// Respond with token validity and claims
	response := ValidateResponse{
		Valid:  true,
		UserID: userID,
		Error:  "",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func userIDToUint(userID string) (uint, error) {
	var id uint
	_, err := fmt.Sscanf(userID, "%d", &id)
	if err != nil {
		return 0, err
	}
	return id, nil
}
