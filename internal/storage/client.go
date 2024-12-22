package storage

import (
	"errors"
	"fmt"
	"github.com/jordanharrington/oauth-service/internal/config"
	"github.com/jordanharrington/oauth-service/internal/model"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"log"
)

type DBClient struct {
	database *gorm.DB
}

func NewDBClient(storageConfig config.StorageConfig) (*DBClient, error) {
	dsn, err := storageConfig.GenerateDSN()
	if err != nil {
		return nil, fmt.Errorf("failed to generate DSN: %w", err)
	}

	var db *gorm.DB
	switch storageConfig.DBType {
	case "postgres":
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	case "mysql":
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	case "sqlserver":
		db, err = gorm.Open(sqlserver.Open(dsn), &gorm.Config{})
	default:
		return nil, fmt.Errorf("unsupported database type: %s", storageConfig.DBType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.AutoMigrate(&model.User{}, &model.RefreshToken{}); err != nil {
		return nil, err
	}

	return &DBClient{
		database: db,
	}, nil
}

// GetUserByUsername retrieves a user from the database by username
func (d *DBClient) GetUserByUsername(username string) (*model.User, error) {
	var user model.User
	// Query the user from the database
	if err := d.database.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (d *DBClient) GetUserByEmail(email string) (*model.User, error) {
	var user model.User
	if err := d.database.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil
}

// GetUserByID retrieves a user by ID
func (d *DBClient) GetUserByID(id string) (*model.User, error) {
	var user model.User
	if err := d.database.Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil
}

// GetRefreshTokenByUserID retrieves a refresh token associated with a user ID
func (d *DBClient) GetRefreshTokenByUserID(id string) (*model.RefreshToken, error) {
	var token model.RefreshToken
	if err := d.database.Where("userid = ?", id).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("token not found")
		}
		return nil, fmt.Errorf("error retrieving token: %w", err)
	}
	return &token, nil
}

// GetRefreshToken retrieves a refresh token by its value
func (d *DBClient) GetRefreshToken(refreshToken string) (*model.RefreshToken, error) {
	var token model.RefreshToken
	if err := d.database.Where("token = ?", refreshToken).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("token not found")
		}
		return nil, fmt.Errorf("error retrieving token: %w", err)
	}
	return &token, nil
}

// DeleteRefreshToken deletes a refresh token by its value
func (d *DBClient) DeleteRefreshToken(refreshToken string) error {
	if err := d.database.Where("token = ?", refreshToken).Delete(&model.RefreshToken{}).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("token not found")
		}
		return fmt.Errorf("error retrieving token: %w", err)
	}
	return nil
}

// DeleteUser deletes a user and all associated refresh tokens
func (d *DBClient) DeleteUser(userID string) error {
	return d.database.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&model.RefreshToken{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", userID).Delete(&model.User{}).Error
	})
}

// CreateUser inserts a new user into the database
func (d *DBClient) CreateUser(user *model.User) error {
	if err := d.database.Create(user).Error; err != nil {
		log.Println("Error creating user:", err)
		return err
	}
	return nil
}

// CreateToken inserts a new token into the database
func (d *DBClient) CreateToken(token *model.RefreshToken) error {
	if err := d.database.Create(token).Error; err != nil {
		log.Println("Error creating user:", err)
		return err
	}
	return nil
}
