package storage

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
)

type Storage struct {
	database *gorm.DB
}

func Init(dst ...interface{}) (*Storage, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		getEnv("DB_HOST", "jivium-db"), getEnv("DB_USER", "user"),
		getEnv("DB_PASSWORD", "password"), getEnv("DB_NAME", "jivium"),
		getEnv("DB_PORT", "5432"))
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.AutoMigrate(dst); err != nil {
		return nil, err
	}

	return &Storage{
		database: db,
	}, nil
}

func (s *Storage) GetDatabase() *gorm.DB {
	return s.database
}

func getEnv(key, fallback string) string {
	val, exists := os.LookupEnv(key)
	if !exists {
		return fallback
	}
	return val
}
