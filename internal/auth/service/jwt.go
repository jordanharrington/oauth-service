package service

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jordanharrington/jivium/internal/auth/storage"
	"time"
)

var secretKey = []byte("your-secret-key") // Store securely

func GenerateJWT(user *storage.User) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   fmt.Sprintf("%d", user.ID),
		Issuer:    "jivium",
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}
