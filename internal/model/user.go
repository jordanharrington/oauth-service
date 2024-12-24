package model

import "time"

// RefreshToken struct defines the refresh token model
type RefreshToken struct {
	ID        string `gorm:"type:char(36);primaryKey"`
	UserID    string `gorm:"type:varchar(191);index"` // Foreign key linking to User.ID
	Token     string `gorm:"type:varchar(191);unique"`
	CreatedAt time.Time
	ExpiresAt time.Time
}

// User struct defines the user model
type User struct {
	ID            string `gorm:"type:char(36);primaryKey"`
	Username      string `gorm:"type:varchar(191);unique"`
	Email         string `gorm:"type:varchar(191);unique"`
	PasswordHash  string `gorm:"type:text"`
	CreatedAt     time.Time
	RefreshTokens []RefreshToken `gorm:"foreignKey:UserID" json:"-"` // Relationship to RefreshToken
}
