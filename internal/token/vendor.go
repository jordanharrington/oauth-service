package token

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jordanharrington/jivium/internal/data"
	"os"
	"time"
)

var (
	UserIdClaimKey = "user_id"
	ExpClaimKey    = "exp"
)

type Vendor struct {
	secreteKey []byte
	refreshKey []byte
}

func NewVendor(keyPath string) (*Vendor, error) {
	keys, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key sig paths")
	}
	return &Vendor{
		secreteKey: keys,
		refreshKey: keys,
	}, nil
}

func (t *Vendor) GenerateJWT(userID uint) (string, error) {
	now := time.Now()
	claims := jwt.StandardClaims{
		Subject:   fmt.Sprintf("%d", userID),
		Issuer:    "jivium-auth",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(t.secreteKey)
}

func (t *Vendor) VerifyJWT(tokenString string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return t.secreteKey, nil
	})
	if err != nil {
		// Check if the error is due to expiration
		var validationError *jwt.ValidationError
		if errors.As(err, &validationError) {
			if validationError.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, fmt.Errorf("token expired")
			}
		}
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	return claims, nil
}

func (t *Vendor) GenerateRefreshToken(user *data.User) (*data.RefreshToken, error) {
	now := time.Now()
	oneWeekFromNow := now.Add(7 * 24 * time.Hour)
	claims := jwt.MapClaims{
		UserIdClaimKey: user.ID,
		ExpClaimKey:    oneWeekFromNow.Unix(),
	}

	if token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(t.refreshKey); err != nil {
		return nil, err
	} else {
		return &data.RefreshToken{
			UserID:    user.ID,
			Token:     token,
			CreatedAt: now,
			ExpiresAt: oneWeekFromNow,
		}, nil
	}
}

func (t *Vendor) VerifyRefreshToken(refreshToken string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return t.refreshKey, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	return claims, nil
}
