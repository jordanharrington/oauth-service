package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewStorageConfig(t *testing.T) {
	t.Setenv("DB_TYPE", "t_postgres")
	t.Setenv("DB_HOST", "t_localhost")
	t.Setenv("DB_PORT", "t_5432")
	t.Setenv("DB_USER", "t_testuser")
	t.Setenv("DB_PASSWORD", "t_testpassword")
	t.Setenv("DB_NAME", "t_testdb")
	t.Setenv("DB_SSLMODE", "t_disable")

	config := NewStorageConfig()

	assert.Equal(t, "t_postgres", config.DBType)
	assert.Equal(t, "t_localhost", config.Host)
	assert.Equal(t, "t_5432", config.Port)
	assert.Equal(t, "t_testuser", config.User)
	assert.Equal(t, "t_testpassword", config.Password)
	assert.Equal(t, "t_testdb", config.DBName)
	assert.Equal(t, "t_disable", config.SSLMode)
}

func TestGenerateDSN(t *testing.T) {
	testCases := []struct {
		name     string
		config   StorageConfig
		expected string
		hasError bool
	}{
		{
			name: "Postgres DSN",
			config: StorageConfig{
				DBType:   "postgres",
				Host:     "localhost",
				Port:     "5432",
				User:     "testuser",
				Password: "testpassword",
				DBName:   "testdb",
				SSLMode:  "disable",
			},
			expected: "host=localhost user=testuser password=testpassword dbname=testdb port=5432 sslmode=disable",
			hasError: false,
		},
		{
			name: "MySQL DSN",
			config: StorageConfig{
				DBType:   "mysql",
				Host:     "localhost",
				Port:     "3306",
				User:     "testuser",
				Password: "testpassword",
				DBName:   "testdb",
			},
			expected: "testuser:testpassword@tcp(localhost:3306)/testdb?charset=utf8mb4&parseTime=True&loc=Local",
			hasError: false,
		},
		{
			name: "SQLite DSN",
			config: StorageConfig{
				DBType: "sqlite",
				DBName: "test.db",
			},
			expected: "test.db",
			hasError: false,
		},
		{
			name: "SQLServer DSN",
			config: StorageConfig{
				DBType:   "sqlserver",
				Host:     "localhost",
				Port:     "1433",
				User:     "testuser",
				Password: "testpassword",
				DBName:   "testdb",
			},
			expected: "sqlserver://testuser:testpassword@localhost:1433?database=testdb",
			hasError: false,
		},
		{
			name: "Unsupported DB Type",
			config: StorageConfig{
				DBType: "unsupported",
			},
			expected: "",
			hasError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dsn, err := tc.config.GenerateDSN()
			if tc.hasError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported database type")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, dsn)
			}
		})
	}
}
