package model

// AuthResponse Contains the full user details along with tokens. It is used during login or registration to provide
// both user information and the authentication tokens.
type AuthResponse struct {
	User         *User  `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// TokenResponse Focused solely on providing refreshed tokens and does not include any user details. It is specifically
// used for refreshing an expired or near-expired token.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
