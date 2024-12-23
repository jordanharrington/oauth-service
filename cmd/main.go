package main

import (
	"github.com/jordanharrington/oauth-service/internal/config"
	"github.com/jordanharrington/oauth-service/internal/handler"
	"github.com/jordanharrington/oauth-service/internal/logger"
	"github.com/jordanharrington/oauth-service/internal/service"
	"github.com/jordanharrington/oauth-service/internal/storage"
	"net/http"
	"os"
)

func main() {
	// setup logging
	logger.InitGlobalLogger()

	// connect to database
	storageConfig := config.NewStorageConfig()
	db, err := storage.NewDBClient(storageConfig)
	if err != nil {
		logger.Log().Fatal().Msgf("Error initializing database: %v", err)
		return
	}
	logger.Log().Info().Msg("database connection established successfully")

	// Create token service
	tokenServiceConfig, err := config.NewTokenConfig()
	if err != nil {
		logger.Log().Fatal().Msgf("Error initializing token service: %v", err)
		return
	}
	tokenService := service.NewTokenService(tokenServiceConfig)
	logger.Log().Info().Msg("created token service")

	// Find and check public key
	pKeyPath := os.Getenv("PUBLIC_KEY_PATH")
	if pKeyPath == "" {
		logger.Log().Fatal().Msg("PUBLIC_KEY_PATH environment variable not set")
		return
	}

	_, err = os.ReadFile(pKeyPath)
	if err != nil {
		logger.Log().Fatal().Msgf("Error reading public key: %v", err)
		return
	}
	logger.Log().Info().Msg("found public key")

	// Create handler
	authService := service.NewAuthService(db, tokenService, pKeyPath)
	h := handler.NewAuthHandler(authService)
	logger.Log().Info().Msg("initializing service")

	// Setup endpoints
	http.HandleFunc("/login", h.Login)
	http.HandleFunc("/logout", h.Logout)
	http.HandleFunc("/register", h.Register)
	http.HandleFunc("/unregister", h.Unregister)
	http.HandleFunc("/refresh", h.Refresh)
	http.HandleFunc("/validate", h.Validate)
	http.HandleFunc("/public-key", h.PublicKey)

	// Listen
	logger.Log().Info().Msg("listening on port 8080")
	err = http.ListenAndServe(":8080", nil)
	logger.Log().Fatal().Msgf("%v", err)
}
