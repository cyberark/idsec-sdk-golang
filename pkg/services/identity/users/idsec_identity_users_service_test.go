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
						"LastLogin": "/Date(1640000000000)/",
						"DirectoryServiceUuid": "dir-uuid-1"
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

	UserMgmtAttrsResponseJSON = `{
		"success": true,
		"Result": {
			"InEverybodyRole": true,
			"OauthClient": false
		}
	}`

	UserMgmtAttrsServiceUserResponseJSON = `{
		"success": true,
		"Result": {
			"InEverybodyRole": false,
			"OauthClient": false
		}
	}`

	UserMgmtAttrsOauthClientResponseJSON = `{
		"success": true,
		"Result": {
			"InEverybodyRole": false,
			"OauthClient": true
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

	UserAttributesSchemaResponseJSON = `{
		"success": true,
		"Result": {
			"Columns": [
				{
					"Name": "CustomAtt_1",
					"Title": "Department",
					"Type": "Text",
					"Description": "User department"
				},
				{
					"Name": "CustomAtt_2",
					"Title": "Cost Center",
					"Type": "Text",
					"Description": "User cost center"
				}
			]
		}
	}`

	UserAttributesSchemaEmptyResponseJSON = `{
		"success": true,
		"Result": {
			"Columns": []
		}
	}`

	UserAttributesResponseJSON = `{
		"success": true,
		"Result": {
			"CustomAtt_1": "Engineering",
			"CustomAtt_2": "CC-1234"
		}
	}`

	UserAttributesEmptyResponseJSON = `{
		"success": true,
		"Result": {}
	}`

	UpsertUserAttributesSchemaResponseJSON = `{
		"success": true
	}`

	DeleteUserAttributesSchemaResponseJSON = `{
		"success": true
	}`

	SetUserAttributesResponseJSON = `{
		"success": true
	}`
)

func TestCreate(t *testing.T) {
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
				service.DirectoriesService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil
				}
				service.DirectoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			},
		},
		{
			name: "success_create_service_user",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Username:      "service.user@example.com",
				Email:         "service.user@example.com",
				DisplayName:   "Service User",
				Password:      "SecurePass123!",
				IsServiceUser: boolPtr(true),
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateUserResponseJSON),
			mockPostError:    nil,
			expectedUser: &usersmodels.IdsecIdentityUser{
				UserID:          "user-123",
				Username:        "service.user@example.com",
				DisplayName:     "Service User",
				Email:           "service.user@example.com",
				InEverybodyRole: boolPtr(false),
				IsServiceUser:   boolPtr(true),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, CreateUserResponseJSON), nil
				}
			},
		},
		{
			name: "success_create_oauth_client",
			createUser: &usersmodels.IdsecIdentityCreateUser{
				Username:      "oauth.client@example.com",
				Email:         "oauth.client@example.com",
				DisplayName:   "OAuth Client",
				Password:      "SecurePass123!",
				IsOauthClient: boolPtr(true),
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateUserResponseJSON),
			mockPostError:    nil,
			expectedUser: &usersmodels.IdsecIdentityUser{
				UserID:          "user-123",
				Username:        "oauth.client@example.com",
				DisplayName:     "OAuth Client",
				Email:           "oauth.client@example.com",
				InEverybodyRole: boolPtr(false),
				IsServiceUser:   boolPtr(true),
				IsOauthClient:   boolPtr(true),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, CreateUserResponseJSON), nil
				}
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

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
			if tt.expectedUser.InEverybodyRole != nil && result.InEverybodyRole != nil {
				if *result.InEverybodyRole != *tt.expectedUser.InEverybodyRole {
					t.Errorf("Expected InEverybodyRole %v, got %v", *tt.expectedUser.InEverybodyRole, *result.InEverybodyRole)
				}
			}
			if tt.expectedUser.IsServiceUser != nil && result.IsServiceUser != nil {
				if *result.IsServiceUser != *tt.expectedUser.IsServiceUser {
					t.Errorf("Expected IsServiceUser %v, got %v", *tt.expectedUser.IsServiceUser, *result.IsServiceUser)
				}
			}
			if tt.expectedUser.IsOauthClient != nil && result.IsOauthClient != nil {
				if *result.IsOauthClient != *tt.expectedUser.IsOauthClient {
					t.Errorf("Expected IsOauthClient %v, got %v", *tt.expectedUser.IsOauthClient, *result.IsOauthClient)
				}
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
						// First call: UpdateUser
						return MockHTTPResponse(http.StatusOK, UpdateUserResponseJSON), nil
					}
					// Second call: userMgmtAttributes (from User call)
					return MockHTTPResponse(http.StatusOK, UserMgmtAttrsResponseJSON), nil
				}
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					// UserAttributes call (from User call)
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "success_update_service_user",
			updateUser: &usersmodels.IdsecIdentityUpdateUser{
				UserID:        "user-123",
				IsServiceUser: boolPtr(true),
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
					return MockHTTPResponse(http.StatusOK, UserMgmtAttrsServiceUserResponseJSON), nil
				}
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "success_update_oauth_client",
			updateUser: &usersmodels.IdsecIdentityUpdateUser{
				UserID:        "user-123",
				IsOauthClient: boolPtr(true),
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
					return MockHTTPResponse(http.StatusOK, UserMgmtAttrsOauthClientResponseJSON), nil
				}
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
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
		{
			name: "error_user_retrieval_after_update_failed",
			updateUser: &usersmodels.IdsecIdentityUpdateUser{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UpdateUserResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UpdateUserResponseJSON), nil
				}
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("failed to retrieve user")
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

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
				UserID:          "user-123",
				Username:        "john.doe@example.com",
				DisplayName:     "John Doe",
				Email:           "john.doe@example.com",
				MobileNumber:    "+1234567890",
				InEverybodyRole: boolPtr(true),
				IsServiceUser:   boolPtr(false),
				IsOauthClient:   boolPtr(false),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					// userMgmtAttributes call
					return MockHTTPResponse(http.StatusOK, UserMgmtAttrsResponseJSON), nil
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					// UserAttributes call
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
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
				UserID:          "user-123",
				Username:        "john.doe@example.com",
				DisplayName:     "John Doe",
				Email:           "john.doe@example.com",
				MobileNumber:    "+1234567890",
				InEverybodyRole: boolPtr(true),
				IsServiceUser:   boolPtr(false),
				IsOauthClient:   boolPtr(false),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserMgmtAttrsResponseJSON), nil
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "success_get_service_user",
			getUser: &usersmodels.IdsecIdentityGetUser{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserQueryResponseJSON),
			mockPostError:    nil,
			expectedUser: &usersmodels.IdsecIdentityUser{
				UserID:          "user-123",
				Username:        "john.doe@example.com",
				DisplayName:     "John Doe",
				Email:           "john.doe@example.com",
				MobileNumber:    "+1234567890",
				InEverybodyRole: boolPtr(false),
				IsServiceUser:   boolPtr(true),
				IsOauthClient:   boolPtr(false),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserMgmtAttrsServiceUserResponseJSON), nil
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "success_get_oauth_client_user",
			getUser: &usersmodels.IdsecIdentityGetUser{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserQueryResponseJSON),
			mockPostError:    nil,
			expectedUser: &usersmodels.IdsecIdentityUser{
				UserID:          "user-123",
				Username:        "john.doe@example.com",
				DisplayName:     "John Doe",
				Email:           "john.doe@example.com",
				MobileNumber:    "+1234567890",
				InEverybodyRole: boolPtr(false),
				IsServiceUser:   boolPtr(true),
				IsOauthClient:   boolPtr(true),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserMgmtAttrsOauthClientResponseJSON), nil
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
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
		{
			name: "error_user_mgmt_attrs_failed",
			getUser: &usersmodels.IdsecIdentityGetUser{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserQueryResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("failed to get user attributes")
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "error_user_custom_attrs_failed",
			getUser: &usersmodels.IdsecIdentityGetUser{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserQueryResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					// userMgmtAttributes succeeds
					return MockHTTPResponse(http.StatusOK, UserMgmtAttrsResponseJSON), nil
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					// UserAttributes fails
					return nil, errors.New("failed to get custom attributes")
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

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
			if tt.expectedUser.InEverybodyRole != nil && result.InEverybodyRole != nil {
				if *result.InEverybodyRole != *tt.expectedUser.InEverybodyRole {
					t.Errorf("Expected InEverybodyRole %v, got %v", *tt.expectedUser.InEverybodyRole, *result.InEverybodyRole)
				}
			}
			if tt.expectedUser.IsServiceUser != nil && result.IsServiceUser != nil {
				if *result.IsServiceUser != *tt.expectedUser.IsServiceUser {
					t.Errorf("Expected IsServiceUser %v, got %v", *tt.expectedUser.IsServiceUser, *result.IsServiceUser)
				}
			}
			if tt.expectedUser.IsOauthClient != nil && result.IsOauthClient != nil {
				if *result.IsOauthClient != *tt.expectedUser.IsOauthClient {
					t.Errorf("Expected IsOauthClient %v, got %v", *tt.expectedUser.IsOauthClient, *result.IsOauthClient)
				}
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

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
				callCount := 0
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						// First call: userMgmtAttributes (from User call)
						return MockHTTPResponse(http.StatusOK, UserMgmtAttrsResponseJSON), nil
					}
					// Second call: ResetUserPassword
					return MockHTTPResponse(http.StatusOK, ResetPasswordResponseJSON), nil
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					// UserAttributes call (from User call)
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "error_user_not_found",
			resetPassword: &usersmodels.IdsecIdentityResetUserPassword{
				Username:    "nonexistent@example.com",
				NewPassword: "NewSecurePass123!",
			},
			mockPostResponse: nil,
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
			resetPassword: &usersmodels.IdsecIdentityResetUserPassword{
				Username:    "john.doe@example.com",
				NewPassword: "NewSecurePass123!",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						// First call: userMgmtAttributes (from User call)
						return MockHTTPResponse(http.StatusOK, UserMgmtAttrsResponseJSON), nil
					}
					// Second call: ResetUserPassword - network error
					return nil, errors.New("network error")
				}
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					// UserAttributes call (from User call)
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "error_user_query_failed",
			resetPassword: &usersmodels.IdsecIdentityResetUserPassword{
				Username:    "john.doe@example.com",
				NewPassword: "NewSecurePass123!",
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoRedrockQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("query failed")
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

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

func TestUserAttributesSchema(t *testing.T) {
	tests := []struct {
		name             string
		mockPostResponse *http.Response
		mockPostError    error
		expectedCount    int
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name:             "success_get_schema_with_columns",
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON),
			mockPostError:    nil,
			expectedCount:    2,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
				}
			},
		},
		{
			name:             "success_get_empty_schema",
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserAttributesSchemaEmptyResponseJSON),
			mockPostError:    nil,
			expectedCount:    0,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesSchemaEmptyResponseJSON), nil
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
		{
			name:             "error_non_200_status",
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
			name:             "error_success_false",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ErrorResponseJSON), nil
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UserAttributesSchema()

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

			if result.TotalCount != tt.expectedCount {
				t.Errorf("Expected %d columns, got %d", tt.expectedCount, result.TotalCount)
			}

			if len(result.Columns) != tt.expectedCount {
				t.Errorf("Expected %d columns in list, got %d", tt.expectedCount, len(result.Columns))
			}
		})
	}
}

func TestUpsertUserAttributesSchema(t *testing.T) {
	tests := []struct {
		name             string
		upsertSchema     *usersmodels.IdsecIdentityUpsertUserAttributesSchema
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_upsert_new_columns",
			upsertSchema: &usersmodels.IdsecIdentityUpsertUserAttributesSchema{
				Columns: []usersmodels.IdsecIdentityUserAttributesSchemaColumn{
					{
						Name:        "CustomAtt_3",
						Title:       "Location",
						Type:        "Text",
						Description: "User location",
					},
				},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UpsertUserAttributesSchemaResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						// First call: get existing schema
						return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
					} else if callCount == 2 {
						// Second call: update schema
						return MockHTTPResponse(http.StatusOK, UpsertUserAttributesSchemaResponseJSON), nil
					}
					// Third call: get updated schema
					return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
				}
			},
		},
		{
			name: "success_update_existing_columns",
			upsertSchema: &usersmodels.IdsecIdentityUpsertUserAttributesSchema{
				Columns: []usersmodels.IdsecIdentityUserAttributesSchemaColumn{
					{
						Name:        "CustomAtt_1",
						Title:       "Department Updated",
						Type:        "Text",
						Description: "Updated department description",
					},
				},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UpsertUserAttributesSchemaResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
					} else if callCount == 2 {
						return MockHTTPResponse(http.StatusOK, UpsertUserAttributesSchemaResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
				}
			},
		},
		{
			name: "error_empty_columns",
			upsertSchema: &usersmodels.IdsecIdentityUpsertUserAttributesSchema{
				Columns: []usersmodels.IdsecIdentityUserAttributesSchemaColumn{},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_get_existing_schema_failed",
			upsertSchema: &usersmodels.IdsecIdentityUpsertUserAttributesSchema{
				Columns: []usersmodels.IdsecIdentityUserAttributesSchemaColumn{
					{
						Name:  "CustomAtt_3",
						Title: "Location",
						Type:  "Text",
					},
				},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("failed to get schema")
				}
			},
		},
		{
			name: "error_update_schema_failed",
			upsertSchema: &usersmodels.IdsecIdentityUpsertUserAttributesSchema{
				Columns: []usersmodels.IdsecIdentityUserAttributesSchemaColumn{
					{
						Name:  "CustomAtt_3",
						Title: "Location",
						Type:  "Text",
					},
				},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
					}
					return nil, errors.New("failed to update schema")
				}
			},
		},
		{
			name: "error_non_200_status",
			upsertSchema: &usersmodels.IdsecIdentityUpsertUserAttributesSchema{
				Columns: []usersmodels.IdsecIdentityUserAttributesSchemaColumn{
					{
						Name:  "CustomAtt_3",
						Title: "Location",
						Type:  "Text",
					},
				},
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
					}
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UpsertUserAttributesSchema(tt.upsertSchema)

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
				t.Errorf("Expected schema result, got nil")
			}
		})
	}
}

func TestDeleteUserAttributesSchema(t *testing.T) {
	tests := []struct {
		name             string
		deleteSchema     *usersmodels.IdsecIdentityDeleteUserAttributesSchema
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_delete_columns_by_names",
			deleteSchema: &usersmodels.IdsecIdentityDeleteUserAttributesSchema{
				ColumnNames: []string{"CustomAtt_1"},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, DeleteUserAttributesSchemaResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						// First call: get existing schema
						return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
					} else if callCount == 2 {
						// Second call: update schema
						return MockHTTPResponse(http.StatusOK, DeleteUserAttributesSchemaResponseJSON), nil
					}
					// Third call: get updated schema
					return MockHTTPResponse(http.StatusOK, UserAttributesSchemaEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "success_delete_columns_by_objects",
			deleteSchema: &usersmodels.IdsecIdentityDeleteUserAttributesSchema{
				Columns: []usersmodels.IdsecIdentityUserAttributesSchemaColumn{
					{Name: "CustomAtt_1"},
					{Name: "CustomAtt_2"},
				},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, DeleteUserAttributesSchemaResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
					} else if callCount == 2 {
						return MockHTTPResponse(http.StatusOK, DeleteUserAttributesSchemaResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, UserAttributesSchemaEmptyResponseJSON), nil
				}
			},
		},
		{
			name:             "error_empty_column_names",
			deleteSchema:     &usersmodels.IdsecIdentityDeleteUserAttributesSchema{},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_get_existing_schema_failed",
			deleteSchema: &usersmodels.IdsecIdentityDeleteUserAttributesSchema{
				ColumnNames: []string{"CustomAtt_1"},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("failed to get schema")
				}
			},
		},
		{
			name: "error_update_schema_failed",
			deleteSchema: &usersmodels.IdsecIdentityDeleteUserAttributesSchema{
				ColumnNames: []string{"CustomAtt_1"},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
					}
					return nil, errors.New("failed to update schema")
				}
			},
		},
		{
			name: "error_non_200_status",
			deleteSchema: &usersmodels.IdsecIdentityDeleteUserAttributesSchema{
				ColumnNames: []string{"CustomAtt_1"},
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesSchemaResponseJSON), nil
					}
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.DeleteUserAttributesSchema(tt.deleteSchema)

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
				t.Errorf("Expected schema result, got nil")
			}
		})
	}
}

func TestUserAttributes(t *testing.T) {
	tests := []struct {
		name             string
		getUserAttrs     *usersmodels.IdsecIdentityGetUserAttributes
		mockPostResponse *http.Response
		mockPostError    error
		expectedCount    int
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_get_user_attributes",
			getUserAttrs: &usersmodels.IdsecIdentityGetUserAttributes{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON),
			mockPostError:    nil,
			expectedCount:    2,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
				}
			},
		},
		{
			name: "success_get_empty_user_attributes",
			getUserAttrs: &usersmodels.IdsecIdentityGetUserAttributes{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON),
			mockPostError:    nil,
			expectedCount:    0,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			getUserAttrs: &usersmodels.IdsecIdentityGetUserAttributes{
				UserID: "user-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			getUserAttrs: &usersmodels.IdsecIdentityGetUserAttributes{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
		{
			name: "error_success_false",
			getUserAttrs: &usersmodels.IdsecIdentityGetUserAttributes{
				UserID: "user-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ErrorResponseJSON), nil
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UserAttributes(tt.getUserAttrs)

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

			if len(result.Attributes) != tt.expectedCount {
				t.Errorf("Expected %d attributes, got %d", tt.expectedCount, len(result.Attributes))
			}

			if result.UserID != tt.getUserAttrs.UserID {
				t.Errorf("Expected user ID %s, got %s", tt.getUserAttrs.UserID, result.UserID)
			}
		})
	}
}

func TestUpsertUserAttributes(t *testing.T) {
	tests := []struct {
		name             string
		upsertAttrs      *usersmodels.IdsecIdentityUpsertUserAttributes
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_upsert_new_attributes",
			upsertAttrs: &usersmodels.IdsecIdentityUpsertUserAttributes{
				UserID: "user-123",
				Attributes: map[string]string{
					"CustomAtt_3": "NewValue",
				},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, SetUserAttributesResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						// First call: get existing attributes
						return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
					} else if callCount == 2 {
						// Second call: set attributes
						return MockHTTPResponse(http.StatusOK, SetUserAttributesResponseJSON), nil
					}
					// Third call: get updated attributes
					return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
				}
			},
		},
		{
			name: "success_update_existing_attributes",
			upsertAttrs: &usersmodels.IdsecIdentityUpsertUserAttributes{
				UserID: "user-123",
				Attributes: map[string]string{
					"CustomAtt_1": "UpdatedValue",
				},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, SetUserAttributesResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
					} else if callCount == 2 {
						return MockHTTPResponse(http.StatusOK, SetUserAttributesResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
				}
			},
		},
		{
			name: "error_get_existing_attributes_failed",
			upsertAttrs: &usersmodels.IdsecIdentityUpsertUserAttributes{
				UserID: "user-123",
				Attributes: map[string]string{
					"CustomAtt_1": "Value",
				},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("failed to get attributes")
				}
			},
		},
		{
			name: "error_set_attributes_failed",
			upsertAttrs: &usersmodels.IdsecIdentityUpsertUserAttributes{
				UserID: "user-123",
				Attributes: map[string]string{
					"CustomAtt_1": "Value",
				},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
					}
					return nil, errors.New("failed to set attributes")
				}
			},
		},
		{
			name: "error_non_200_status",
			upsertAttrs: &usersmodels.IdsecIdentityUpsertUserAttributes{
				UserID: "user-123",
				Attributes: map[string]string{
					"CustomAtt_1": "Value",
				},
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
					}
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UpsertUserAttributes(tt.upsertAttrs)

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
				t.Errorf("Expected attributes result, got nil")
			}
		})
	}
}

func TestDeleteUserAttributes(t *testing.T) {
	tests := []struct {
		name             string
		deleteAttrs      *usersmodels.IdsecIdentityDeleteUserAttributes
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityUsersService)
	}{
		{
			name: "success_delete_attributes_by_names",
			deleteAttrs: &usersmodels.IdsecIdentityDeleteUserAttributes{
				UserID:         "user-123",
				AttributeNames: []string{"CustomAtt_1"},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, SetUserAttributesResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						// First call: get existing attributes
						return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
					} else if callCount == 2 {
						// Second call: set attributes
						return MockHTTPResponse(http.StatusOK, SetUserAttributesResponseJSON), nil
					}
					// Third call: get updated attributes
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "success_delete_attributes_by_map",
			deleteAttrs: &usersmodels.IdsecIdentityDeleteUserAttributes{
				UserID: "user-123",
				Attributes: map[string]string{
					"CustomAtt_1": "any_value",
					"CustomAtt_2": "any_value",
				},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, SetUserAttributesResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
					} else if callCount == 2 {
						return MockHTTPResponse(http.StatusOK, SetUserAttributesResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, UserAttributesEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "error_get_existing_attributes_failed",
			deleteAttrs: &usersmodels.IdsecIdentityDeleteUserAttributes{
				UserID:         "user-123",
				AttributeNames: []string{"CustomAtt_1"},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("failed to get attributes")
				}
			},
		},
		{
			name: "error_set_attributes_failed",
			deleteAttrs: &usersmodels.IdsecIdentityDeleteUserAttributes{
				UserID:         "user-123",
				AttributeNames: []string{"CustomAtt_1"},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
					}
					return nil, errors.New("failed to set attributes")
				}
			},
		},
		{
			name: "error_non_200_status",
			deleteAttrs: &usersmodels.IdsecIdentityDeleteUserAttributes{
				UserID:         "user-123",
				AttributeNames: []string{"CustomAtt_1"},
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityUsersService) {
				callCount := 0
				service.DoUserAttributesPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, UserAttributesResponseJSON), nil
					}
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.DeleteUserAttributes(tt.deleteAttrs)

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
				t.Errorf("Expected attributes result, got nil")
			}
		})
	}
}

// boolPtr is a helper function to create a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}
