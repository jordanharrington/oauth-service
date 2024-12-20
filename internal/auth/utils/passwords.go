package utils

import (
	"golang.org/x/crypto/bcrypt"
	"log"
)

// ComparePasswords compares a provided password with the hashed password from the database
func ComparePasswords(providedPassword, storedHash string) bool {
	// Convert stored hash into bytes
	hashedPassword := []byte(storedHash)

	// Compare the provided password with the hashed password
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(providedPassword))
	if err != nil {
		// Log the error (but do not give any hints to the user)
		log.Println("Password comparison failed:", err)
		return false
	}
	return true
}
