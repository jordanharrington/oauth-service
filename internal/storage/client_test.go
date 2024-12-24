package storage

import (
	"context"
	"github.com/jordanharrington/oauth-service/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"testing"
)

func setupPostgresContainer(t *testing.T) (testcontainers.Container, config.StorageConfig) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:latest",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "testuser",
			"POSTGRES_PASSWORD": "testpassword",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp"),
	}

	postgresContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	assert.NoError(t, err)

	host, err := postgresContainer.Host(ctx)
	assert.NoError(t, err)

	port, err := postgresContainer.MappedPort(ctx, "5432")
	assert.NoError(t, err)

	storageConfig := config.StorageConfig{
		DBType:   "postgres",
		Host:     host,
		Port:     port.Port(),
		User:     "testuser",
		Password: "testpassword",
		DBName:   "testdb",
		SSLMode:  "disable",
	}

	return postgresContainer, storageConfig
}

func setupMySQLContainer(t *testing.T) (testcontainers.Container, config.StorageConfig) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "mysql:latest",
		ExposedPorts: []string{"3306/tcp"},
		Env: map[string]string{
			"MYSQL_ROOT_PASSWORD": "rootpassword",
			"MYSQL_USER":          "testuser",
			"MYSQL_PASSWORD":      "testpassword",
			"MYSQL_DATABASE":      "testdb",
		},
		WaitingFor: wait.ForListeningPort("3306/tcp"),
	}

	mysqlContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	assert.NoError(t, err)

	host, err := mysqlContainer.Host(ctx)
	assert.NoError(t, err)

	port, err := mysqlContainer.MappedPort(ctx, "3306")
	assert.NoError(t, err)

	storageConfig := config.StorageConfig{
		DBType:   "mysql",
		Host:     host,
		Port:     port.Port(),
		User:     "testuser",
		Password: "testpassword",
		DBName:   "testdb",
	}

	return mysqlContainer, storageConfig
}

func TestNewDBClientWithPostgres(t *testing.T) {
	postgresContainer, storageConfig := setupPostgresContainer(t)
	defer func() {
		assert.NoError(t, postgresContainer.Terminate(context.Background()))
	}()

	t.Run("Success", func(t *testing.T) {
		client, err := NewDBClient(storageConfig)
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestNewDBClientWithMySQL(t *testing.T) {
	sqlContainer, storageConfig := setupMySQLContainer(t)
	defer func() {
		assert.NoError(t, sqlContainer.Terminate(context.Background()))
	}()

	t.Run("Success", func(t *testing.T) {
		client, err := NewDBClient(storageConfig)
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}
