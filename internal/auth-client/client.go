package auth_client

// ValidateTokenResponse represents the response from the auth token when validating a token
type ValidateTokenResponse struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// AuthClient defines the contract for the auth auth-client
type AuthClient interface {
	ValidateToken(token string) (*ValidateTokenResponse, error)
	GenerateToken(userID uint, username string, email string) (string, error)
}
