package users

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/models"
)

// MockHTTPResponse creates a mock HTTP response with the given status code and body.
func MockHTTPResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

// MockPostFunc creates a mock function for POST operations that returns the provided response.
func MockPostFunc(response *http.Response, err error) func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
		return response, err
	}
}

func MockGetFunc(response *http.Response, err error) func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	return func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
		return response, err
	}
}

func MockISPAuth() *auth.IdsecISPAuth {
	return &auth.IdsecISPAuth{
		IdsecAuthBase: &auth.IdsecAuthBase{
			Token: &authmodels.IdsecToken{
				Token:      "",
				TokenType:  authmodels.JWT,
				Username:   "mock-username@mock-domain.cyberark.cloud",
				Endpoint:   "https://mock-endpoint",
				AuthMethod: authmodels.Identity,
				Metadata: map[string]interface{}{
					"env": "dev",
				},
			},
		},
	}
}

// Sample JSON responses for testing
const (
	CreateUserResponseJSON = `{
		"success": true,
		"Result": "user-123"
	}`

	CreateUserFailureResponseJSON = `{
		"success": false,
		"error": "user creation failed"
	}`

	UpdateUserResponseJSON = `{
		"success": true
	}`

	DeleteUserResponseJSON = `{
		"success": true
	}`

	DeleteUsersResponseJSON = `{
		"success": true
	}`

	ResetPasswordResponseJSON = `{
		"success": true
	}`

	UserQueryResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"ID": "user-123",
						"Username": "john.doe@example.com",
						"DisplayName": "John Doe",
						"Email": "john.doe@example.com",
						"MobileNumber": "+1234567890",
						"LastLogin": "/Date(1640000000000)/"
					}
				}
			]
		}
	}`

	UserQueryNotFoundResponseJSON = `{
		"success": true,
		"Result": {
			"Results": []
		}
	}`

	ListUsersResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"ID": "user-1",
						"Username": "user1@example.com",
						"DisplayName": "User One",
						"Email": "user1@example.com",
						"MobileNumber": "+1111111111",
						"LastLogin": "/Date(1640000000000)/"
					}
				},
				{
					"Row": {
						"ID": "user-2",
						"Username": "user2@example.com",
						"DisplayName": "User Two",
						"Email": "user2@example.com",
						"MobileNumber": "+2222222222",
						"LastLogin": "/Date(1640000000000)/"
					}
				}
			]
		}
	}`

	ListUsersEmptyResponseJSON = `{
		"success": true,
		"Result": {
			"Results": []
		}
	}`

	UserInfoResponseJSON = `{
		"sub": "user-123",
		"user": "john.doe@example.com",
		"auth_level": "admin"
	}`

	DirectoryListResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"Service": "CDS",
						"DirectoryServiceUUID": "dir-uuid-1"
					}
				}
			]
		}
	}`

	TenantSuffixResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Entities": [
						{
							"Key": "example.com"
						}
					]
				}
			]
		}
	}`

	ErrorResponseJSON = `{
		"success": false,
		"error": "operation failed"
	}`
)

func TestCreateUser(t *testing.T) {
	tests := []struct {
		name             string
		createUser       *usersmodels.IdsecIdentityCreateUser
		mockPostResponse *http.Response
		mockPostError    error
		expectedUser     *usersmodels.IdsecIdentityUser
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_create_user_with_full_details",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Username:    "john.doe@example.com",
				Email:       "john.doe@example.com",
				DisplayName: "John Doe",
				Password:    "SecurePass123!",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateUserResponseJSON),
			mockPostError:    nil,
			expectedUser: &usersmodels.IdsecIdentityUser{
				UserID:      "user-123",
				Username:    "john.doe@example.com",
				DisplayName: "John Doe",
				Email:       "john.doe@example.com",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, CreateUserResponseJSON), nil
				}
			},
		},
		{
			name: "success_create_user_with_auto_generated_display_name",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Username: "john.doe@example.com",
				Email:    "john.doe@example.com",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateUserResponseJSON),
			mockPostError:    nil,
			expectedUser: &usersmodels.IdsecIdentityUser{
				UserID:   "user-123",
				Username: "john.doe@example.com",
				Email:    "john.doe@example.com",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, CreateUserResponseJSON), nil
				}
			},
		},
		{
			name: "success_create_user_with_suffix_resolution",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Username: "john.doe",
				Email:    "john.doe@example.com",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateUserResponseJSON),
			mockPostError:    nil,
			expectedUser: &usersmodels.IdsecIdentityUser{
				UserID:   "user-123",
				Username: "john.doe@example.com",
				Email:    "john.doe@example.com",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, CreateUserResponseJSON), nil
				}
				service.directoriesService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil
				}
				service.directoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			},
		},
		{
			name: "error_missing_username",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Email: "john.doe@example.com",
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_missing_email",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Username: "john.doe@example.com",
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_http_request_failed",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Username: "john.doe@example.com",
				Email:    "john.doe@example.com",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Username: "john.doe@example.com",
				Email:    "john.doe@example.com",
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
		{
			name: "error_success_false",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Username: "john.doe@example.com",
				Email:    "john.doe@example.com",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateUserFailureResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, CreateUserFailureResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityUsersService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityUsersService: %v", err)
			}
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.CreateUser(tt.createUser)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result.UserID != tt.expectedUser.UserID {
				t.Errorf("Expected user ID %s, got %s", tt.expectedUser.UserID, result.UserID)
			}
			if result.Username != tt.expectedUser.Username {
				t.Errorf("Expected username %s, got %s", tt.expectedUser.Username, result.Username)
			}
			if result.Email != tt.expectedUser.Email {
				t.Errorf("Expected email %s, got %s", tt.expectedUser.Email, result.Email)
			}
		})
	}
}

func TestUpdateUser(t *testing.T) {
	tests := []struct {
		name             string
		updateUser       *usersmodels.IdsecIdentityUpdateUser
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_update_user",
			updateUser: &usersmodels.IdsecIdentityUpdateUser{
				UserID:      "user-123",
				DisplayName: "John Updated",
				Email:       "john.updated@example.com",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UpdateUserResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UpdateUserResponseJSON), nil
					}
					return nil, nil
				}
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			updateUser: &usersmodels.IdsecIdentityUpdateUser{
				UserID: "user-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			updateUser: &usersmodels.IdsecIdentityUpdateUser{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityUsersService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityUsersService: %v", err)
			}
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UpdateUser(tt.updateUser)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result == nil {
				t.Errorf("Expected user result, got nil")
			}
		})
	}
}

func TestDeleteUser(t *testing.T) {
	tests := []struct {
		name             string
		deleteUser       *usersmodels.IdsecIdentityDeleteUser
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_delete_user_by_id",
			deleteUser: &usersmodels.IdsecIdentityDeleteUser{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, DeleteUserResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, DeleteUserResponseJSON), nil
				}
			},
		},
		{
			name: "success_delete_user_by_username",
			deleteUser: &usersmodels.IdsecIdentityDeleteUser{
				Username: "john.doe@example.com",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, DeleteUserResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, DeleteUserResponseJSON), nil
				}
			},
		},
		{
			name:             "error_no_user_id_or_username",
			deleteUser:       &usersmodels.IdsecIdentityDeleteUser{},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_http_request_failed",
			deleteUser: &usersmodels.IdsecIdentityDeleteUser{
				UserID: "user-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityUsersService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityUsersService: %v", err)
			}
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			err = service.DeleteUser(tt.deleteUser)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestDeleteUsers(t *testing.T) {
	tests := []struct {
		name             string
		deleteUsers      *usersmodels.IdsecIdentityDeleteUsers
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_delete_multiple_users",
			deleteUsers: &usersmodels.IdsecIdentityDeleteUsers{
				UserIDs: []string{"user-1", "user-2", "user-3"},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, DeleteUsersResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, DeleteUsersResponseJSON), nil
				}
			},
		},
		{
			name:             "error_empty_user_ids",
			deleteUsers:      &usersmodels.IdsecIdentityDeleteUsers{UserIDs: []string{}},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_http_request_failed",
			deleteUsers: &usersmodels.IdsecIdentityDeleteUsers{
				UserIDs: []string{"user-1"},
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityUsersService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityUsersService: %v", err)
			}
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			err = service.DeleteUsers(tt.deleteUsers)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestUser(t *testing.T) {
	tests := []struct {
		name             string
		getUser          *usersmodels.IdsecIdentityGetUser
		mockPostResponse *http.Response
		mockPostError    error
		expectedUser     *usersmodels.IdsecIdentityUser
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_get_user_by_id",
			getUser: &usersmodels.IdsecIdentityGetUser{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserQueryResponseJSON),
			mockPostError:    nil,
			expectedUser: &usersmodels.IdsecIdentityUser{
				UserID:       "user-123",
				Username:     "john.doe@example.com",
				DisplayName:  "John Doe",
				Email:        "john.doe@example.com",
				MobileNumber: "+1234567890",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
			},
		},
		{
			name: "success_get_user_by_username",
			getUser: &usersmodels.IdsecIdentityGetUser{
				Username: "john.doe@example.com",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserQueryResponseJSON),
			mockPostError:    nil,
			expectedUser: &usersmodels.IdsecIdentityUser{
				UserID:       "user-123",
				Username:     "john.doe@example.com",
				DisplayName:  "John Doe",
				Email:        "john.doe@example.com",
				MobileNumber: "+1234567890",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
			},
		},
		{
			name:             "error_no_user_id_or_username",
			getUser:          &usersmodels.IdsecIdentityGetUser{},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_user_not_found",
			getUser: &usersmodels.IdsecIdentityGetUser{
				UserID: "nonexistent-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserQueryNotFoundResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryNotFoundResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			getUser: &usersmodels.IdsecIdentityGetUser{
				UserID: "user-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityUsersService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityUsersService: %v", err)
			}
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.User(tt.getUser)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result.UserID != tt.expectedUser.UserID {
				t.Errorf("Expected user ID %s, got %s", tt.expectedUser.UserID, result.UserID)
			}
			if result.Username != tt.expectedUser.Username {
				t.Errorf("Expected username %s, got %s", tt.expectedUser.Username, result.Username)
			}
		})
	}
}

func TestListUsers(t *testing.T) {
	tests := []struct {
		name             string
		mockPostResponse *http.Response
		mockPostError    error
		expectedCount    int
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name:             "success_list_users",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListUsersResponseJSON),
			mockPostError:    nil,
			expectedCount:    2,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListUsersResponseJSON), nil
				}
			},
		},
		{
			name:             "success_list_empty_users",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListUsersEmptyResponseJSON),
			mockPostError:    nil,
			expectedCount:    0,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListUsersEmptyResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityUsersService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityUsersService: %v", err)
			}
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			pages, err := service.ListUsers()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			totalCount := 0
			for page := range pages {
				totalCount += len(page.Items)
			}

			if totalCount != tt.expectedCount {
				t.Errorf("Expected %d users, got %d", tt.expectedCount, totalCount)
			}
		})
	}
}

func TestResetUserPassword(t *testing.T) {
	tests := []struct {
		name             string
		resetPassword    *usersmodels.IdsecIdentityResetUserPassword
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_reset_password",
			resetPassword: &usersmodels.IdsecIdentityResetUserPassword{
				Username:    "john.doe@example.com",
				NewPassword: "NewSecurePass123!",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ResetPasswordResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ResetPasswordResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			resetPassword: &usersmodels.IdsecIdentityResetUserPassword{
				Username:    "john.doe@example.com",
				NewPassword: "NewSecurePass123!",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityUsersService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityUsersService: %v", err)
			}
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			err = service.ResetUserPassword(tt.resetPassword)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestUserInfo(t *testing.T) {
	tests := []struct {
		name             string
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name:             "success_get_user_info",
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserInfoResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserInfoResponseJSON), nil
				}
			},
		},
		{
			name:             "error_http_request_failed",
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityUsersService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityUsersService: %v", err)
			}
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UserInfo()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result == nil {
				t.Errorf("Expected user info result, got nil")
			}
		})
	}
}

func TestUsersStats(t *testing.T) {
	tests := []struct {
		name             string
		mockPostResponse *http.Response
		mockPostError    error
		expectedCount    int
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name:             "success_get_users_stats",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListUsersResponseJSON),
			mockPostError:    nil,
			expectedCount:    2,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListUsersResponseJSON), nil
				}
			},
		},
		{
			name:             "success_get_users_stats_empty",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListUsersEmptyResponseJSON),
			mockPostError:    nil,
			expectedCount:    0,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListUsersEmptyResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityUsersService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityUsersService: %v", err)
			}
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UsersStats()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result.UsersCount != tt.expectedCount {
				t.Errorf("Expected users count %d, got %d", tt.expectedCount, result.UsersCount)
			}
		})
	}
}
