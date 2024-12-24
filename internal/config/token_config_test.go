package config

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

const (
	EnvSecretKey         = "SECRET_KEY"
	EnvSecretKeyPath     = "SECRET_KEY_PATH"
	EnvRefreshKey        = "REFRESH_KEY"
	EnvServiceName       = "SERVICE_NAME"
	EnvTokenExpiry       = "TOKEN_EXPIRY"
	EnvRefreshExpiry     = "REFRESH_EXPIRY"
	DefaultTokenExpiry   = time.Hour
	DefaultRefreshExpiry = 7 * 24 * time.Hour
)

func setupEnv(envs map[string]string, t *testing.T) {
	for key, value := range envs {
		if key != "" {
			t.Setenv(key, value)
		}
	}
}

func TestLoadSecret(t *testing.T) {
	cases := []struct {
		name           string
		envVar         string
		envValue       string
		envPathVar     string
		envPathValue   string
		expected       []byte
		expectErr      bool
		expectedErrMsg string
		setupFile      bool
	}{
		{
			name:      "EnvironmentVariableSet",
			envVar:    EnvSecretKey,
			envValue:  "test-secret",
			expected:  []byte("test-secret"),
			expectErr: false,
		},
		{
			name:         "EnvironmentVariableFilePath",
			envVar:       EnvSecretKey,
			envPathVar:   EnvSecretKeyPath,
			envPathValue: "test-secret-file.txt",
			expected:     []byte("file-secret"),
			expectErr:    false,
			setupFile:    true,
		},
		{
			name:           "MissingEnvironmentVariable",
			envVar:         "MISSING_SECRET",
			expectErr:      true,
			expectedErrMsg: "neither MISSING_SECRET nor MISSING_SECRET_PATH is set",
		},
		{
			name:           "FileReadError",
			envVar:         EnvSecretKey,
			envPathVar:     EnvSecretKeyPath,
			envPathValue:   "missing-file.txt",
			expectErr:      true,
			expectedErrMsg: "failed to read secret from file",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupEnv(map[string]string{
				tc.envVar:     tc.envValue,
				tc.envPathVar: tc.envPathValue,
			}, t)

			if tc.setupFile {
				err := os.WriteFile(tc.envPathValue, tc.expected, 0644)
				assert.NoError(t, err)
				defer func(name string) {
					err := os.Remove(name)
					if err != nil {
						t.Fatal()
					}
				}(tc.envPathValue)
			}

			secret, err := LoadSecret(tc.envVar)
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, secret)
			}
		})
	}
}

func TestLoadConfigDuration(t *testing.T) {
	cases := []struct {
		name           string
		envVar         string
		envValue       string
		defaultValue   time.Duration
		expected       time.Duration
		expectDefault  bool
		expectedErrMsg string
	}{
		{
			name:         "EnvironmentVariableSet",
			envVar:       EnvTokenExpiry,
			envValue:     "3600",
			defaultValue: DefaultTokenExpiry,
			expected:     time.Hour,
		},
		{
			name:           "InvalidEnvironmentVariable",
			envVar:         EnvTokenExpiry,
			envValue:       "invalid",
			defaultValue:   DefaultTokenExpiry,
			expected:       DefaultTokenExpiry,
			expectedErrMsg: "Invalid value for TOKEN_EXPIRY, using default",
		},
		{
			name:         "EnvironmentVariableNotSet",
			envVar:       "MISSING_EXPIRY",
			defaultValue: DefaultTokenExpiry,
			expected:     DefaultTokenExpiry,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupEnv(map[string]string{
				tc.envVar: tc.envValue,
			}, t)

			duration := LoadConfigDuration(tc.envVar, tc.defaultValue)
			assert.Equal(t, tc.expected, duration)
		})
	}
}

func TestNewTokenConfig(t *testing.T) {
	cases := []struct {
		name           string
		envs           map[string]string
		expected       *TokenConfig
		expectErr      bool
		expectedErrMsg string
	}{
		{
			name: "SuccessfulConfigLoad",
			envs: map[string]string{
				EnvSecretKey:     "test-secret",
				EnvRefreshKey:    "refresh-secret",
				EnvServiceName:   "test-service",
				EnvTokenExpiry:   "3600",
				EnvRefreshExpiry: "604800",
			},
			expected: &TokenConfig{
				SecretKey:     []byte("test-secret"),
				RefreshKey:    []byte("refresh-secret"),
				ServiceName:   "test-service",
				TokenExpiry:   DefaultTokenExpiry,
				RefreshExpiry: DefaultRefreshExpiry,
			},
			expectErr: false,
		},
		{
			name: "MissingSecretKey",
			envs: map[string]string{
				EnvRefreshKey:  "refresh-secret",
				EnvServiceName: "test-service",
			},
			expectErr:      true,
			expectedErrMsg: "failed to load secret key",
		},
		{
			name: "MissingRefreshKey",
			envs: map[string]string{
				EnvSecretKey:   "test-secret",
				EnvServiceName: "test-service",
			},
			expectErr:      true,
			expectedErrMsg: "failed to load refresh key",
		},
		{
			name: "MissingServiceName",
			envs: map[string]string{
				EnvSecretKey:  "test-secret",
				EnvRefreshKey: "refresh-secret",
			},
			expectErr:      true,
			expectedErrMsg: "failed to load service name",
		},
		{
			name: "InvalidTokenExpiry",
			envs: map[string]string{
				EnvSecretKey:   "test-secret",
				EnvRefreshKey:  "refresh-secret",
				EnvServiceName: "test-service",
				EnvTokenExpiry: "invalid",
			},
			expected: &TokenConfig{
				SecretKey:     []byte("test-secret"),
				RefreshKey:    []byte("refresh-secret"),
				ServiceName:   "test-service",
				TokenExpiry:   DefaultTokenExpiry,
				RefreshExpiry: DefaultRefreshExpiry,
			},
			expectErr: false,
		},
		{
			name: "InvalidRefreshExpiry",
			envs: map[string]string{
				EnvSecretKey:     "test-secret",
				EnvRefreshKey:    "refresh-secret",
				EnvServiceName:   "test-service",
				EnvRefreshExpiry: "invalid",
			},
			expected: &TokenConfig{
				SecretKey:     []byte("test-secret"),
				RefreshKey:    []byte("refresh-secret"),
				ServiceName:   "test-service",
				TokenExpiry:   DefaultTokenExpiry,
				RefreshExpiry: DefaultRefreshExpiry,
			},
			expectErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupEnv(tc.envs, t)

			config, err := NewTokenConfig()
			if tc.expectErr {
				assert.Nil(t, config)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)
				assert.Equal(t, tc.expected.SecretKey, config.SecretKey)
				assert.Equal(t, tc.expected.RefreshKey, config.RefreshKey)
				assert.Equal(t, tc.expected.ServiceName, config.ServiceName)
				assert.Equal(t, tc.expected.TokenExpiry, config.TokenExpiry)
				assert.Equal(t, tc.expected.RefreshExpiry, config.RefreshExpiry)
			}
		})
	}
}
