package main

import (
	"fmt"
	"github.com/jordanharrington/jivium/internal/auth/handler"
	"github.com/jordanharrington/jivium/internal/auth/storage"
	"log"
	"net/http"
)

func main() {
	if err := storage.InitDB(); err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	fmt.Println("Database connection established successfully!")

	http.HandleFunc("/login", handler.Login)
	http.HandleFunc("/register", handler.Register)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
