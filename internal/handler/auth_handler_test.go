package handler

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jordanharrington/oauth-service/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	testAccessToken  = "testAccess"
	testRefreshToken = "testRefresh"
	testPublicKey    = "testPublicKey"

	testUser = &model.User{
		ID:           uuid.New().String(),
		Username:     "test",
		Email:        "test@test.com",
		PasswordHash: "passwords",
		CreatedAt:    time.Now(),
	}

	testAuthResponse = &model.AuthResponse{
		User:         testUser,
		AccessToken:  testAccessToken,
		RefreshToken: testRefreshToken,
	}

	testTokenResponse = &model.TokenResponse{
		AccessToken:  testAccessToken,
		RefreshToken: testRefreshToken,
	}
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Login(username, password string) (*model.AuthResponse, error) {
	args := m.Called(username, password)
	return args.Get(0).(*model.AuthResponse), args.Error(1)
}

func (m *MockAuthService) CreateUser(username, email, password string) (*model.AuthResponse, error) {
	args := m.Called(username, email, password)
	return args.Get(0).(*model.AuthResponse), args.Error(1)
}

func (m *MockAuthService) RenewTokens(refreshToken string) (*model.TokenResponse, error) {
	args := m.Called(refreshToken)
	return args.Get(0).(*model.TokenResponse), args.Error(1)
}

func (m *MockAuthService) InvalidateRefreshToken(refreshToken string) error {
	args := m.Called(refreshToken)
	return args.Error(0)
}

func (m *MockAuthService) ValidateAccessToken(token string) (bool, error) {
	args := m.Called(token)
	return args.Bool(0), args.Error(1)
}

func (m *MockAuthService) PublicKey() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) AuthenticateUser(username, password string) (*model.User, error) {
	args := m.Called(username, password)
	return args.Get(0).(*model.User), args.Error(1)
}

func (m *MockAuthService) DeleteUser(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

func closeResponseBody(t *testing.T, body io.ReadCloser) {
	err := body.Close()
	if err != nil {
		t.Fatalf("failed to close response body: %s", err)
	}
}

func decodeResponseBody(t *testing.T, body io.ReadCloser, v interface{}) {
	err := json.NewDecoder(body).Decode(v)
	if err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
}

func makeRequest(method, path, body, contentType string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	return req
}

func assertErrorResponse(t *testing.T, res *http.Response, expectedStatus int, expectedMessage string) {
	assert.Equal(t, expectedStatus, res.StatusCode)
	responseBody, _ := io.ReadAll(res.Body)
	assert.Contains(t, string(responseBody), expectedMessage)
}

func AuthResponsesEqual(a, b model.AuthResponse) bool {
	if a.User == nil && b.User != nil || a.User != nil && b.User == nil {
		return false
	}

	if a.User != nil && b.User != nil {
		if a.User.ID != b.User.ID || a.User.Username != b.User.Username || a.User.Email != b.User.Email {
			return false
		}
	}

	return a.AccessToken == b.AccessToken && a.RefreshToken == b.RefreshToken
}

func setupHandlerTest(configureMock func(mockAuthService *MockAuthService)) (*authHandler, *httptest.ResponseRecorder, *MockAuthService) {
	mockAuthService := new(MockAuthService)
	if configureMock != nil {
		configureMock(mockAuthService)
	}
	handler := NewAuthHandler(mockAuthService)
	recorder := httptest.NewRecorder()
	return handler.(*authHandler), recorder, mockAuthService
}

func setupLoginTest(mockResponse *model.AuthResponse, mockError error) (*authHandler, *httptest.ResponseRecorder, *MockAuthService) {
	return setupHandlerTest(func(mockAuthService *MockAuthService) {
		mockAuthService.On("Login", mock.Anything, mock.Anything).Return(mockResponse, mockError)
	})
}

func setupLogoutTest(mockError error) (*authHandler, *httptest.ResponseRecorder, *MockAuthService) {
	return setupHandlerTest(func(mockAuthService *MockAuthService) {
		mockAuthService.On("InvalidateRefreshToken", mock.Anything).Return(mockError)
	})
}

func setupRegisterTest(mockError error) (*authHandler, *httptest.ResponseRecorder, *MockAuthService) {
	return setupHandlerTest(func(mockAuthService *MockAuthService) {
		mockAuthService.On("CreateUser", mock.Anything, mock.Anything, mock.Anything).Return(testAuthResponse, mockError)
	})
}

func setupRefreshTest(mockError error) (*authHandler, *httptest.ResponseRecorder, *MockAuthService) {
	return setupHandlerTest(func(mockAuthService *MockAuthService) {
		mockAuthService.On("RenewTokens", mock.Anything).Return(testTokenResponse, mockError)
	})
}

func setupPublicKeyTest(mockError error, mockPublicKey string) (*authHandler, *httptest.ResponseRecorder, *MockAuthService) {
	return setupHandlerTest(func(mockAuthService *MockAuthService) {
		mockAuthService.On("PublicKey").Return(mockPublicKey, mockError)
	})
}

func setupUnregisterTest(mockAuthError, mockDeleteError error) (*authHandler, *httptest.ResponseRecorder, *MockAuthService) {
	return setupHandlerTest(func(mockAuthService *MockAuthService) {
		mockAuthService.On("AuthenticateUser", mock.Anything, mock.Anything).Return(testUser, mockAuthError)
		mockAuthService.On("DeleteUser", mock.Anything).Return(mockDeleteError)
	})
}

func setupValidateTest(mockError error, mockIsValid bool) (*authHandler, *httptest.ResponseRecorder, *MockAuthService) {
	return setupHandlerTest(func(mockAuthService *MockAuthService) {
		mockAuthService.On("ValidateAccessToken", mock.Anything).Return(mockIsValid, mockError)
	})
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *model.AuthResponse
		mockError      error
		method         string
		contentType    string
		body           string
		expectedStatus int
		expectedError  string
		validateBody   func(t *testing.T, body io.ReadCloser)
	}{
		{
			name:           "Success",
			mockResponse:   testAuthResponse,
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"username": "validuser", "password": "validpass"}`,
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body io.ReadCloser) {
				var response model.AuthResponse
				decodeResponseBody(t, body, &response)
				assert.True(t, AuthResponsesEqual(*testAuthResponse, response))
			},
		},
		{
			name:           "InvalidPayload",
			mockResponse:   nil,
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"username": "validuser"`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request payload",
		},
		{
			name:           "UnsupportedMethod",
			mockResponse:   nil,
			mockError:      nil,
			method:         http.MethodGet,
			contentType:    "",
			body:           "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedError:  "Method not allowed",
		},
		{
			name:           "ContentTypeNotJSON",
			mockResponse:   nil,
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "text/plain",
			body:           `{"username": "validuser", "password": "validpass"}`,
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedError:  "Invalid content type",
		},
		{
			name:           "RequestError",
			mockResponse:   nil,
			mockError:      model.NewRequestError("invalid username or password"),
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"username": "invaliduser", "password": "invalidpass"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid username or password",
		},
		{
			name:           "ServiceError",
			mockResponse:   nil,
			mockError:      model.NewServiceError("database failure"),
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"username": "validuser", "password": "validpass"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Internal server error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, recorder, _ := setupLoginTest(tc.mockResponse, tc.mockError)

			req := makeRequest(tc.method, "/login", tc.body, tc.contentType)

			handler.Login(recorder, req)

			res := recorder.Result()
			defer closeResponseBody(t, res.Body)

			assert.Equal(t, tc.expectedStatus, res.StatusCode)

			if tc.expectedError != "" {
				assertErrorResponse(t, res, tc.expectedStatus, tc.expectedError)
			} else if tc.validateBody != nil {
				tc.validateBody(t, res.Body)
			}
		})
	}
}

func TestLogout(t *testing.T) {
	tests := []struct {
		name           string
		mockError      error
		method         string
		contentType    string
		body           string
		expectedStatus int
		expectedError  string
		validateBody   func(t *testing.T, body io.ReadCloser)
	}{
		{
			name:           "Success",
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"refresh_token": "validRefreshToken"}`,
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body io.ReadCloser) {
				responseBody, _ := io.ReadAll(body)
				assert.Contains(t, string(responseBody), "Logged out successfully")
			},
		},
		{
			name:           "InvalidPayload",
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"refresh_token":`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request payload",
		},
		{
			name:           "UnsupportedMethod",
			mockError:      nil,
			method:         http.MethodGet,
			contentType:    "",
			body:           "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedError:  "Method not allowed",
		},
		{
			name:           "ContentTypeNotJSON",
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "text/plain",
			body:           `{"refresh_token": "validRefreshToken"}`,
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedError:  "Invalid content type",
		},
		{
			name:           "RequestError",
			mockError:      model.NewRequestError("invalid refresh token"),
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"refresh_token": "invalidRefreshToken"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid refresh token",
		},
		{
			name:           "ServiceError",
			mockError:      model.NewServiceError("database failure"),
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"refresh_token": "validRefreshToken"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Internal server error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, recorder, _ := setupLogoutTest(tc.mockError)

			req := makeRequest(tc.method, "/logout", tc.body, tc.contentType)

			handler.Logout(recorder, req)

			res := recorder.Result()
			defer closeResponseBody(t, res.Body)

			assert.Equal(t, tc.expectedStatus, res.StatusCode)

			if tc.expectedError != "" {
				assertErrorResponse(t, res, tc.expectedStatus, tc.expectedError)
			} else if tc.validateBody != nil {
				tc.validateBody(t, res.Body)
			}
		})
	}
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name           string
		mockError      error
		method         string
		contentType    string
		body           string
		expectedStatus int
		expectedError  string
		validateBody   func(t *testing.T, body io.ReadCloser)
	}{
		{
			name:           "Success",
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"username": "testuser", "email": "test@example.com", "password": "securepassword"}`,
			expectedStatus: http.StatusCreated,
			validateBody: func(t *testing.T, body io.ReadCloser) {
				var response model.AuthResponse
				decodeResponseBody(t, body, &response)
				assert.True(t, AuthResponsesEqual(*testAuthResponse, response))
			},
		},
		{
			name:           "InvalidPayload",
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"username": "testuser"`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request payload",
		},
		{
			name:           "UnsupportedMethod",
			mockError:      nil,
			method:         http.MethodGet,
			contentType:    "",
			body:           "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedError:  "Method not allowed",
		},
		{
			name:           "ContentTypeNotJSON",
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "text/plain",
			body:           `{"username": "testuser", "email": "test@example.com", "password": "securepassword"}`,
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedError:  "Invalid content type",
		},
		{
			name:           "RequestError",
			mockError:      model.NewRequestError("username is already taken"),
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"username": "existinguser", "email": "test@example.com", "password": "securepassword"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "username is already taken",
		},
		{
			name:           "ServiceError",
			mockError:      model.NewServiceError("database failure"),
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"username": "testuser", "email": "test@example.com", "password": "securepassword"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Internal server error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, recorder, _ := setupRegisterTest(tc.mockError)

			req := makeRequest(tc.method, "/register", tc.body, tc.contentType)

			handler.Register(recorder, req)

			res := recorder.Result()
			defer closeResponseBody(t, res.Body)

			assert.Equal(t, tc.expectedStatus, res.StatusCode)

			if tc.expectedError != "" {
				assertErrorResponse(t, res, tc.expectedStatus, tc.expectedError)
			} else if tc.validateBody != nil {
				tc.validateBody(t, res.Body)
			}
		})
	}
}

func TestRefresh(t *testing.T) {
	tests := []struct {
		name           string
		mockError      error
		method         string
		contentType    string
		body           string
		expectedStatus int
		expectedError  string
		validateBody   func(t *testing.T, body io.ReadCloser)
	}{
		{
			name:           "Success",
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"refresh_token": "validRefreshToken"}`,
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body io.ReadCloser) {
				var response model.TokenResponse
				decodeResponseBody(t, body, &response)
				assert.Equal(t, testTokenResponse.AccessToken, response.AccessToken)
				assert.Equal(t, testTokenResponse.RefreshToken, response.RefreshToken)
			},
		},
		{
			name:           "InvalidPayload",
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"refresh_token":`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request payload",
		},
		{
			name:           "UnsupportedMethod",
			mockError:      nil,
			method:         http.MethodGet,
			contentType:    "",
			body:           "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedError:  "Method not allowed",
		},
		{
			name:           "ContentTypeNotJSON",
			mockError:      nil,
			method:         http.MethodPost,
			contentType:    "text/plain",
			body:           `{"refresh_token": "validRefreshToken"}`,
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedError:  "Invalid content type",
		},
		{
			name:           "RequestError",
			mockError:      model.NewRequestError("invalid refresh token"),
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"refresh_token": "invalidRefreshToken"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid refresh token",
		},
		{
			name:           "ServiceError",
			mockError:      model.NewServiceError("database failure"),
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"refresh_token": "validRefreshToken"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Internal server error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, recorder, _ := setupRefreshTest(tc.mockError)

			req := makeRequest(tc.method, "/refresh", tc.body, tc.contentType)

			handler.Refresh(recorder, req)

			res := recorder.Result()
			defer closeResponseBody(t, res.Body)

			assert.Equal(t, tc.expectedStatus, res.StatusCode)

			if tc.expectedError != "" {
				assertErrorResponse(t, res, tc.expectedStatus, tc.expectedError)
			} else if tc.validateBody != nil {
				tc.validateBody(t, res.Body)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name           string
		mockError      error
		mockIsValid    bool
		method         string
		contentType    string
		body           string
		expectedStatus int
		expectedError  string
		validateBody   func(t *testing.T, body io.ReadCloser)
	}{
		{
			name:           "Success",
			mockError:      nil,
			mockIsValid:    true,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"token": "validAccessToken"}`,
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body io.ReadCloser) {
				var response model.ValidateResponse
				decodeResponseBody(t, body, &response)
				assert.True(t, response.Valid)
			},
		},
		{
			name:           "InvalidPayload",
			mockError:      nil,
			mockIsValid:    true,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"token":`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request payload",
		},
		{
			name:           "UnsupportedMethod",
			mockError:      nil,
			mockIsValid:    true,
			method:         http.MethodGet,
			contentType:    "",
			body:           "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedError:  "Method not allowed",
		},
		{
			name:           "ContentTypeNotJSON",
			mockError:      nil,
			mockIsValid:    true,
			method:         http.MethodPost,
			contentType:    "text/plain",
			body:           `{"token": "validAccessToken"}`,
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedError:  "Invalid content type",
		},
		{
			name:           "InvalidToken",
			mockError:      nil,
			mockIsValid:    false,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"token": "invalidAccessToken"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Invalid token",
		},
		{
			name:           "RequestError",
			mockError:      model.NewRequestError("invalid token"),
			mockIsValid:    false,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"token": "invalidAccessToken"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid token",
		},
		{
			name:           "ServiceError",
			mockError:      model.NewServiceError("database failure"),
			mockIsValid:    false,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           `{"token": "validAccessToken"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Internal server error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, recorder, _ := setupValidateTest(tc.mockError, tc.mockIsValid)

			req := makeRequest(tc.method, "/validate", tc.body, tc.contentType)

			handler.Validate(recorder, req)

			res := recorder.Result()
			defer closeResponseBody(t, res.Body)

			assert.Equal(t, tc.expectedStatus, res.StatusCode)

			if tc.expectedError != "" {
				assertErrorResponse(t, res, tc.expectedStatus, tc.expectedError)
			} else if tc.validateBody != nil {
				tc.validateBody(t, res.Body)
			}
		})
	}
}

func TestPublicKey(t *testing.T) {
	tests := []struct {
		name           string
		mockError      error
		mockPublicKey  string
		method         string
		contentType    string
		expectedStatus int
		expectedError  string
		validateBody   func(t *testing.T, body io.ReadCloser)
	}{
		{
			name:           "Success",
			mockError:      nil,
			mockPublicKey:  testPublicKey,
			method:         http.MethodGet,
			contentType:    "application/json",
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body io.ReadCloser) {
				var response model.PublicKeyResponse
				decodeResponseBody(t, body, &response)
				assert.Equal(t, testPublicKey, response.PublicKey)
			},
		},
		{
			name:           "UnsupportedMethod",
			mockError:      nil,
			mockPublicKey:  testPublicKey,
			method:         http.MethodPost,
			contentType:    "application/json",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedError:  "Method not allowed",
		},
		{
			name:           "ContentTypeNotJSON",
			mockError:      nil,
			mockPublicKey:  testPublicKey,
			method:         http.MethodGet,
			contentType:    "text/plain",
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedError:  "Invalid content type",
		},
		{
			name:           "ServiceError",
			mockError:      model.NewServiceError("database failure"),
			mockPublicKey:  "",
			method:         http.MethodGet,
			contentType:    "application/json",
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Internal server error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, recorder, _ := setupPublicKeyTest(tc.mockError, tc.mockPublicKey)

			req := makeRequest(tc.method, "/public-key", "", tc.contentType)

			handler.PublicKey(recorder, req)

			res := recorder.Result()
			defer closeResponseBody(t, res.Body)

			assert.Equal(t, tc.expectedStatus, res.StatusCode)

			if tc.expectedError != "" {
				assertErrorResponse(t, res, tc.expectedStatus, tc.expectedError)
			} else if tc.validateBody != nil {
				tc.validateBody(t, res.Body)
			}
		})
	}
}

func TestUnregister(t *testing.T) {
	tests := []struct {
		name           string
		authError      error
		deleteError    error
		method         string
		contentType    string
		body           string
		expectedStatus int
		expectedError  string
		validateBody   func(t *testing.T, body io.ReadCloser)
	}{
		{
			name:           "Success",
			authError:      nil,
			deleteError:    nil,
			method:         http.MethodDelete,
			contentType:    "application/json",
			body:           `{"username": "testuser", "password": "securepassword"}`,
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body io.ReadCloser) {
				responseBody, _ := io.ReadAll(body)
				assert.Contains(t, string(responseBody), "User unregistered successfully")
			},
		},
		{
			name:           "InvalidPayload",
			authError:      nil,
			deleteError:    nil,
			method:         http.MethodDelete,
			contentType:    "application/json",
			body:           `{"username": "testuser"`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request payload",
		},
		{
			name:           "UnsupportedMethod",
			authError:      nil,
			deleteError:    nil,
			method:         http.MethodPost,
			contentType:    "application/json",
			body:           "",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedError:  "Method not allowed",
		},
		{
			name:           "ContentTypeNotJSON",
			authError:      nil,
			deleteError:    nil,
			method:         http.MethodDelete,
			contentType:    "text/plain",
			body:           `{"username": "testuser", "password": "securepassword"}`,
			expectedStatus: http.StatusUnsupportedMediaType,
			expectedError:  "Invalid content type",
		},
		{
			name:           "AuthenticationFailure",
			authError:      model.NewRequestError("invalid username or password"),
			deleteError:    nil,
			method:         http.MethodDelete,
			contentType:    "application/json",
			body:           `{"username": "invaliduser", "password": "wrongpassword"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid username or password",
		},
		{
			name:           "DeleteUserFailure",
			authError:      nil,
			deleteError:    model.NewServiceError("database failure"),
			method:         http.MethodDelete,
			contentType:    "application/json",
			body:           `{"username": "testuser", "password": "securepassword"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Internal server error",
		},
		{
			name:           "AuthenticationServiceError",
			authError:      model.NewServiceError("database failure"),
			deleteError:    nil,
			method:         http.MethodDelete,
			contentType:    "application/json",
			body:           `{"username": "testuser", "password": "securepassword"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Internal server error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, recorder, _ := setupUnregisterTest(tc.authError, tc.deleteError)

			req := makeRequest(tc.method, "/unregister", tc.body, tc.contentType)

			handler.Unregister(recorder, req)

			res := recorder.Result()
			defer closeResponseBody(t, res.Body)

			assert.Equal(t, tc.expectedStatus, res.StatusCode)

			if tc.expectedError != "" {
				assertErrorResponse(t, res, tc.expectedStatus, tc.expectedError)
			} else if tc.validateBody != nil {
				tc.validateBody(t, res.Body)
			}
		})
	}
}

func TestHandleServiceError(t *testing.T) {
	requestError := model.NewRequestError("invalid input")
	serviceError := model.NewServiceError("database failure")
	unknownError := errors.New("some unknown error")

	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Request Error",
			err:            requestError,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid input\n",
		},
		{
			name:           "Service Error",
			err:            serviceError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error\n",
		},
		{
			name:           "Unknown Error",
			err:            unknownError,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Unknown error\n",
		},
	}

	h := authHandler{nil}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			h.handleServiceError(recorder, tt.err)

			assert.Equal(t, tt.expectedStatus, recorder.Code)
			assert.Equal(t, tt.expectedBody, recorder.Body.String())
		})
	}
}
