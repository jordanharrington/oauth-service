package auth_client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultAuthClient is the default implementation of AuthClient
type DefaultAuthClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewDefaultAuthClient creates a new DefaultAuthClient instance
func NewDefaultAuthClient(baseURL string) *DefaultAuthClient {
	return &DefaultAuthClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// ValidateToken sends a request to the auth token to validate a JWT
func (c *DefaultAuthClient) ValidateToken(token string) (*ValidateTokenResponse, error) {
	url := fmt.Sprintf("%s/validate", c.BaseURL)

	reqBody, _ := json.Marshal(map[string]string{
		"token": token,
	})

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("invalid or expired token")
	}

	var result ValidateTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GenerateToken sends a request to the auth token to generate a new token
func (c *DefaultAuthClient) GenerateToken(userID uint, username string, email string) (string, error) {
	url := fmt.Sprintf("%s/generate", c.BaseURL)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"user_id":  userID,
		"username": username,
		"email":    email,
	})

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to generate token")
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Token, nil
}
