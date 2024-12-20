package config

import "os"

var Config struct {
	DBHost     string
	DBUser     string
	DBPassword string
	DBName     string
	DBPort     string
}

func Init() {
	// Initialize environment variables for DB configuration
	Config.DBHost = getEnv("DB_HOST", "jivium-db")
	Config.DBUser = getEnv("DB_USER", "user")
	Config.DBPassword = getEnv("DB_PASSWORD", "password")
	Config.DBName = getEnv("DB_NAME", "jivium")
	Config.DBPort = getEnv("DB_PORT", "5432")
}

func getEnv(key, fallback string) string {
	val, exists := os.LookupEnv(key)
	if !exists {
		return fallback
	}
	return val
}
