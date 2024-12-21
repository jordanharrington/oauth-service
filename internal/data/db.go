package data

import (
	"errors"
	"fmt"
	"github.com/jordanharrington/jivium/internal/storage"
	"gorm.io/gorm"
	"log"
	"time"
)

// User struct defines the user model
type User struct {
	ID            uint   `gorm:"primaryKey"`
	Username      string `gorm:"unique"`
	Email         string `gorm:"unique"`
	PasswordHash  string
	CreatedAt     time.Time
	RefreshTokens []RefreshToken `gorm:"foreignKey:UserID"` // Relationship to RefreshToken
}

type RefreshToken struct {
	ID        uint      `gorm:"primaryKey"` // Unique ID for the token entry
	UserID    uint      `gorm:"index"`      // Foreign key to link the token to a user
	Token     string    `gorm:"unique"`     // The refresh token string (must be unique)
	CreatedAt time.Time // When the token was created
	ExpiresAt time.Time // When the token expires
}

type DBClient struct {
	database *storage.Storage
}

func NewDBClient(s *storage.Storage) *DBClient {
	return &DBClient{
		database: s,
	}
}

// GetUserByUsername retrieves a user from the database by username
func (d *DBClient) GetUserByUsername(username string) (*User, error) {
	var user User
	// Query the user from the database
	if err := d.database.GetDatabase().Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (d *DBClient) GetUserByEmail(email string) (*User, error) {
	var user User
	if err := d.database.GetDatabase().Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil
}

// CreateUser inserts a new user into the database
func (d *DBClient) CreateUser(user *User) error {
	if err := d.database.GetDatabase().Create(user).Error; err != nil {
		log.Println("Error creating user:", err)
		return err
	}
	return nil
}

// CreateToken inserts a new token into the database
func (d *DBClient) CreateToken(token *RefreshToken) error {
	if err := d.database.GetDatabase().Create(token).Error; err != nil {
		log.Println("Error creating user:", err)
		return err
	}
	return nil
}
