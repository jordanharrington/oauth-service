package config

import (
	"fmt"
	"github.com/jordanharrington/oauth-service/internal/logger"
	"os"
	"strconv"
	"time"
)

type TokenConfig struct {
	SecretKey     []byte
	RefreshKey    []byte
	ServiceName   string
	TokenExpiry   time.Duration
	RefreshExpiry time.Duration
}

// LoadSecret retrieves a secret from an environment variable or a file
func LoadSecret(envVar string) ([]byte, error) {
	// Check if the environment variable is set
	secret := os.Getenv(envVar)
	if secret != "" {
		// If it's directly set, return it as bytes
		return []byte(secret), nil
	}

	// Check if the environment variable points to a file path
	secretPath := os.Getenv(envVar + "_PATH")
	if secretPath == "" {
		return nil, fmt.Errorf("neither %s nor %s_PATH is set", envVar, envVar+"_PATH")
	}

	// Read the secret from the file
	secretBytes, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from file %s: %w", secretPath, err)
	}

	return secretBytes, nil
}

// LoadConfigDuration retrieves a duration from an environment variable or uses a default
func LoadConfigDuration(envVar string, fallback time.Duration) time.Duration {
	val := os.Getenv(envVar)
	if val == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(val)
	if err != nil {
		logger.Log().Info().Msgf("Invalid value for %s, using default: %v\n", envVar, fallback)
		return fallback
	}

	return time.Duration(parsed) * time.Second
}

// NewTokenConfig initializes the TokenConfig by loading secrets and configuration values
func NewTokenConfig() (*TokenConfig, error) {
	secretKey, err := LoadSecret("SECRET_KEY")
	if err != nil {
		return nil, fmt.Errorf("failed to load secret key: %w", err)
	}

	refreshKey, err := LoadSecret("REFRESH_KEY")
	if err != nil {
		return nil, fmt.Errorf("failed to load refresh key: %w", err)
	}

	serviceNameBytes, err := LoadSecret("SERVICE_NAME")
	if err != nil {
		return nil, fmt.Errorf("failed to load service name: %w", err)
	}
	serviceName := string(serviceNameBytes)

	tokenExpiry := LoadConfigDuration("TOKEN_EXPIRY", time.Hour)
	refreshExpiry := LoadConfigDuration("REFRESH_EXPIRY", 7*24*time.Hour)

	return &TokenConfig{
		SecretKey:     secretKey,
		RefreshKey:    refreshKey,
		ServiceName:   serviceName,
		TokenExpiry:   tokenExpiry,
		RefreshExpiry: refreshExpiry,
	}, nil
}
