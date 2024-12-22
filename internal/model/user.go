package model

import "time"

// RefreshToken struct defines the refresh token model
type RefreshToken struct {
	ID        string `gorm:"type:uuid;primaryKey"`
	UserID    string `gorm:"type:uuid;index"` // Foreign key linking to User.ID
	Token     string `gorm:"unique"`
	CreatedAt time.Time
	ExpiresAt time.Time
}

// User struct defines the user model
type User struct {
	ID            string `gorm:"type:uuid;primaryKey"`
	Username      string `gorm:"unique"`
	Email         string `gorm:"unique"`
	PasswordHash  string
	CreatedAt     time.Time
	RefreshTokens []RefreshToken `gorm:"foreignKey:UserID" json:"-"` // Relationship to RefreshToken
}
