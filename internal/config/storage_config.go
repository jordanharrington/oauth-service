package config

import (
	"fmt"
	"os"
)

type StorageConfig struct {
	DBType   string
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

func NewStorageConfig() StorageConfig {
	return StorageConfig{
		DBType:   os.Getenv("DB_TYPE"),
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
	}
}

// GenerateDSN creates the Data Source Name (DSN) string based on the DB type
func (c *StorageConfig) GenerateDSN() (string, error) {
	switch c.DBType {
	case "postgres":
		return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
			c.Host, c.User, c.Password, c.DBName, c.Port, c.SSLMode), nil
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			c.User, c.Password, c.Host, c.Port, c.DBName), nil
	case "sqlite":
		return c.DBName, nil // For SQLite, DBName is the file path
	case "sqlserver":
		return fmt.Sprintf("sqlserver://%s:%s@%s:%s?database=%s",
			c.User, c.Password, c.Host, c.Port, c.DBName), nil
	default:
		return "", fmt.Errorf("unsupported database type: %s", c.DBType)
	}
}
