package main

import (
	"fmt"
	"github.com/jordanharrington/oauth-service/internal/config"
	"github.com/jordanharrington/oauth-service/internal/handler"
	"github.com/jordanharrington/oauth-service/internal/service"
	"github.com/jordanharrington/oauth-service/internal/storage"
	"log"
	"net/http"
	"os"
)

func main() {
	storageConfig := config.NewStorageConfig()
	db, err := storage.NewDBClient(storageConfig)
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	fmt.Println("database connection established successfully")

	tokenServiceConfig, err := config.NewTokenConfig()
	if err != nil {
		log.Fatalf("Error initializing token service: %v", err)
	}
	tokenService := service.NewTokenService(tokenServiceConfig)
	fmt.Println("created token service")

	pKeyPath := os.Getenv("PUBLIC_KEY_PATH")
	if pKeyPath == "" {
		log.Fatal("PUBLIC_KEY_PATH environment variable not set")
	}

	_, err = os.ReadFile(pKeyPath)
	if err != nil {
		log.Fatalf("Error reading public key: %v", err)
	}
	fmt.Println("found public key")

	authService := service.NewAuthService(db, tokenService, pKeyPath)
	h := handler.NewAuthHandler(authService)
	fmt.Println("initializing service")

	http.HandleFunc("/login", h.Login)
	http.HandleFunc("/logout", h.Logout)
	http.HandleFunc("/register", h.Register)
	http.HandleFunc("/unregister", h.Unregister)
	http.HandleFunc("/refresh", h.Refresh)
	http.HandleFunc("/validate", h.Validate)
	http.HandleFunc("/public-key", h.PublicKey)

	fmt.Println("listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
