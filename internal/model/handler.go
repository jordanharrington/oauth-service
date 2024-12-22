package model

// LoginRequest Used for submitting user credentials to log in.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ValidateRequest Used for verifying the validity of a JWT token.
type ValidateRequest struct {
	Token string `json:"token"`
}

// ValidateResponse Used for verifying the validity of a JWT token.
type ValidateResponse struct {
	Valid bool `json:"valid"`
}

// RegisterRequest Used for creating a new user in the system.
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RefreshRequest Used for obtaining a new access token using a refresh token.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// PublicKeyResponse Used for retrieving the public key for validating tokens locally in other services.
type PublicKeyResponse struct {
	PublicKey string `json:"public_key"`
}

// LogoutRequest Used for logging out a user.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// UnregisterRequest Used for unregistering a user
type UnregisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
