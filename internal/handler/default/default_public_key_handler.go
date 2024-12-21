package _default

import (
	"net/http"
	"os"
)

type DefaultPublicKeyHandler struct {
	publicKeyPath string
}

func NewDefaultPublicKeyHandler(publicKeyPath string) *DefaultPublicKeyHandler {
	return &DefaultPublicKeyHandler{
		publicKeyPath: publicKeyPath,
	}
}

// PublicKey serves the public key for JWT verification
func (d *DefaultPublicKeyHandler) PublicKey(w http.ResponseWriter, _ *http.Request) {
	// Load the public key from a file or environment
	publicKey, err := os.ReadFile(d.publicKeyPath)
	if err != nil {
		http.Error(w, "Failed to load public key", http.StatusInternalServerError)
		return
	}

	// Set response headers for caching and content type
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "max-age=3600") // Cache for 1 hour
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(publicKey)
}
