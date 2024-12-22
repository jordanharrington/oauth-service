package service

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/jordanharrington/oauth-service/internal/config"
	"github.com/jordanharrington/oauth-service/internal/model"
	"time"
)

type TokenService interface {
	GenerateAccessToken(userID string) (string, error)
	GenerateRefreshToken(userID string) (*model.RefreshToken, error)
	ValidateRefreshToken(tokenString string) (*jwt.StandardClaims, error)
}

type tokenService struct {
	secretKey     []byte
	refreshKey    []byte
	serviceName   string
	tokenExpiry   time.Duration
	refreshExpiry time.Duration
}

func NewTokenService(config *config.TokenConfig) TokenService {
	return &tokenService{
		secretKey:     config.SecretKey,
		refreshKey:    config.RefreshKey,
		serviceName:   config.ServiceName,
		tokenExpiry:   config.TokenExpiry,
		refreshExpiry: config.RefreshExpiry,
	}
}

func (t *tokenService) GenerateAccessToken(userID string) (string, error) {
	now := time.Now()
	claims := jwt.StandardClaims{
		Subject:   userID,
		Issuer:    t.serviceName,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(t.tokenExpiry).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(t.secretKey)
}

func (t *tokenService) GenerateRefreshToken(userID string) (*model.RefreshToken, error) {
	now := time.Now()
	expiry := now.Add(t.refreshExpiry)
	claims := jwt.StandardClaims{
		Subject:   userID,
		Issuer:    t.serviceName,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiry.Unix(),
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.refreshKey)
	if err != nil {
		return nil, err
	}

	return &model.RefreshToken{
		Token:     token,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: expiry,
		ID:        uuid.New().String(),
	}, nil
}

func (t *tokenService) ValidateRefreshToken(tokenString string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method matches
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return t.refreshKey, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}

	// Check if issued by service
	if claims.Issuer != t.serviceName {
		return nil, fmt.Errorf("invalid token issuer: %s", claims.Issuer)
	}

	// Check if the token has expired
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token has expired")
	}

	return claims, nil
}
