package service

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/jordanharrington/oauth-service/internal/model"
	"github.com/jordanharrington/oauth-service/internal/storage"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"strings"
	"time"
)

// AuthService defines the interface for the authentication service
type AuthService interface {
	Login(username, password string) (*model.AuthResponse, error)
	CreateUser(username, email, password string) (*model.AuthResponse, error)
	RenewTokens(refreshToken string) (*model.TokenResponse, error)
	InvalidateRefreshToken(refreshToken string) error
	ValidateAccessToken(token string) (bool, error)
	PublicKey() (string, error)
	AuthenticateUser(username, password string) (*model.User, error)
	DeleteUser(userID string) error
}

type authService struct {
	database *storage.DBClient
	tokenSvc TokenService
	pKeyPath string
}

func NewAuthService(database *storage.DBClient, tokenSvc TokenService, pKeyPath string) AuthService {
	return &authService{
		database: database,
		tokenSvc: tokenSvc,
		pKeyPath: pKeyPath,
	}
}

func (s *authService) CreateUser(username, email, password string) (*model.AuthResponse, error) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(email) == "" || strings.TrimSpace(password) == "" {
		return nil, errors.New("username, email, and password are required")
	}

	existingUser, err := s.database.GetUserByUsername(username)
	if err == nil && existingUser != nil {
		return nil, errors.New("username is already taken")
	}

	existingUser, err = s.database.GetUserByEmail(email)
	if err == nil && existingUser != nil {
		return nil, errors.New("email is already in use")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		return nil, errors.New("failed to hash password")
	}

	newUser := &model.User{
		ID:           uuid.New().String(),
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	err = s.database.CreateUser(newUser)
	if err != nil {
		log.Println("Error saving user:", err)
		return nil, errors.New("failed to save user to the database")
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(newUser.ID)
	if err != nil {
		log.Println("Error generating access token:", err)
		return nil, errors.New("failed to generate access token")
	}

	refreshToken, err := s.tokenSvc.GenerateRefreshToken(newUser.ID)
	if err != nil {
		log.Println("Error generating refresh token:", err)
		return nil, errors.New("failed to generate refresh token")
	}

	err = s.database.CreateToken(refreshToken)
	if err != nil {
		log.Println("Error storing refresh token:", err)
		return nil, errors.New("failed to store refresh token")
	}

	return &model.AuthResponse{
		User:         newUser,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}, nil
}

func (s *authService) RenewTokens(refreshToken string) (*model.TokenResponse, error) {
	claims, err := s.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	userID := claims.Id

	storedToken, err := s.database.GetRefreshTokenByUserID(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve refresh token from database: %w", err)
	}
	if storedToken.Token != refreshToken || storedToken.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token is invalid or expired")
	}

	user, err := s.database.GetUserByID(userID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := s.tokenSvc.GenerateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	err = s.database.CreateToken(newRefreshToken)
	if err != nil {
		return nil, err
	}

	return &model.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken.Token,
	}, nil
}

func (s *authService) ValidateAccessToken(accessToken string) (bool, error) {
	parsedToken, err := jwt.Parse(accessToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		publicKeyBytes, err := os.ReadFile(s.pKeyPath)
		if err != nil {
			return "", fmt.Errorf("failed to read public key: %w", err)
		}

		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		return publicKey, nil
	})

	if err != nil {
		return false, fmt.Errorf("failed to validate accessToken: %w", err)
	}

	if !parsedToken.Valid {
		return false, fmt.Errorf("invalid accessToken")
	}

	return true, nil
}

func (s *authService) PublicKey() (string, error) {
	publicKeyBytes, err := os.ReadFile(s.pKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read public key: %w", err)
	}

	return string(publicKeyBytes), nil
}

func (s *authService) Login(username, password string) (*model.AuthResponse, error) {
	user, err := s.database.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	accessToken, err := s.tokenSvc.GenerateAccessToken(user.ID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.tokenSvc.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, err
	}

	err = s.database.CreateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	return &model.AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken.Token,
	}, nil
}

func (s *authService) InvalidateRefreshToken(refreshToken string) error {
	token, err := s.database.GetRefreshToken(refreshToken)
	if err != nil || token == nil {
		return fmt.Errorf("refresh token not found")
	}

	return s.database.DeleteRefreshToken(refreshToken)
}

func (s *authService) AuthenticateUser(username, password string) (*model.User, error) {
	user, err := s.database.GetUserByUsername(username)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	return user, nil
}

func (s *authService) DeleteUser(userID string) error {
	return s.database.DeleteUser(userID)
}
