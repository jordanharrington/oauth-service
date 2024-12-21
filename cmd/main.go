package main

import (
	"fmt"
	"github.com/jordanharrington/jivium/internal/handler"
	"github.com/jordanharrington/jivium/internal/storage"
	"log"
	"net/http"
	"os"
)

func main() {
	db, err := storage.Init()
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	fmt.Println("database connection established successfully!")

	keyPath := os.Getenv("KEY_PATH")
	fmt.Println("found key config map")

	h, err := handler.Init(db, keyPath)
	if err != nil {
		log.Fatalf("Error initializing handler: %v", err)
	}

	http.HandleFunc("/login", h.Login)
	http.HandleFunc("/register", h.Register)
	http.HandleFunc("/refresh", h.Refresh)
	http.HandleFunc("/validate", h.Validate)
	http.HandleFunc("/public-key", h.PublicKey)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
