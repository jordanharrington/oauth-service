package storage

import (
	"errors"
	"fmt"
	"github.com/jordanharrington/jivium/internal/auth/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"time"
)

// User struct defines the user model
type User struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"unique"`
	Email        string `gorm:"unique"`
	PasswordHash string
	CreatedAt    time.Time
}

// Session struct defines the session model
type Session struct {
	ID        uint `gorm:"primaryKey"`
	UserID    uint `gorm:"index"`
	Token     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

var DB *gorm.DB

func InitDB() error {
	// Init the DB config
	config.Init()
	// Set up the database connection
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		config.Config.DBHost, config.Config.DBUser, config.Config.DBPassword, config.Config.DBName, config.Config.DBPort)
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	// Auto-migrate: Create or update tables based on the Go struct models
	if err := DB.AutoMigrate(&User{}, &Session{}); err != nil {
		return err
	}

	log.Println("Database connection established and tables migrated successfully!")
	return nil
}

// GetUserByUsername retrieves a user from the database by username
func GetUserByUsername(username string) (*User, error) {
	var user User
	// Query the user from the database
	if err := DB.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email
func GetUserByEmail(email string) (*User, error) {
	var user User
	if err := DB.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil
}

// CreateUser inserts a new user into the database
func CreateUser(user *User) error {
	if err := DB.Create(user).Error; err != nil {
		log.Println("Error creating user:", err)
		return err
	}
	return nil
}
