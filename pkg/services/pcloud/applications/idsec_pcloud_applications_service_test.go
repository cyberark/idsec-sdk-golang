package applications

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	applicationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/applications/models"
)

// BoolPtr is a helper function to create a pointer to a bool value.
func BoolPtr(b bool) *bool {
	return &b
}

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

// MockGetFunc creates a mock function for GET operations that returns the provided response.
func MockGetFunc(response *http.Response, err error) func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	return func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
		return response, err
	}
}

// MockDeleteFunc creates a mock function for DELETE operations that returns the provided response.
func MockDeleteFunc(response *http.Response, err error) func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
	return func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
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
	ApplicationResponseJSON = `{
		"application": {
			"app_i_d": "app-123",
			"app_name": "TestApp",
			"description": "Test Application",
			"location": "\\Location",
			"disabled": false,
			"business_owner_f_name": "John",
			"business_owner_l_name": "Doe",
			"business_owner_email": "john.doe@example.com"
		}
	}`

	ApplicationsListResponseJSON = `{
		"application": [
			{
				"app_i_d": "app-1",
				"app_name": "App1",
				"description": "Application 1",
				"location": "\\Location1",
				"disabled": false,
				"business_owner_f_name": "John",
				"business_owner_l_name": "Doe",
				"business_owner_email": "john.doe@example.com"
			},
			{
				"app_i_d": "app-2",
				"app_name": "App2",
				"description": "Application 2",
				"location": "\\Location2",
				"disabled": true,
				"business_owner_f_name": "Jane",
				"business_owner_l_name": "Smith",
				"business_owner_email": "jane.smith@example.com"
			}
		]
	}`

	AuthMethodResponseJSON = `{
		"authentication": [
			{
				"auth_i_d": "auth-123",
				"auth_type": "hash",
				"auth_value": "test-hash",
				"comment": "Test auth method"
			}
		]
	}`

	AuthMethodsListResponseJSON = `{
		"authentication": [
			{
				"auth_i_d": "auth-1",
				"auth_type": "hash",
				"auth_value": "hash1"
			},
			{
				"auth_i_d": "auth-2",
				"auth_type": "path",
				"auth_value": "/test/path"
			}
		]
	}`

	EmptyAuthMethodsResponseJSON = `{
		"authentication": []
	}`

	ErrorResponseJSON = `{
		"error": "operation failed"
	}`
)

func TestCreateApplication(t *testing.T) {
	tests := []struct {
		name              string
		createApplication *applicationsmodels.IdsecPCloudCreateApplication
		mockPostResponse  *http.Response
		mockGetResponse   *http.Response
		mockPostError     error
		expectedError     bool
		setupMock         func(service *IdsecPCloudApplicationsService)
	}{
		{
			name: "success_create_application",
			createApplication: &applicationsmodels.IdsecPCloudCreateApplication{
				AppID:       "app-123",
				Description: "Test Application",
				Location:    "\\Location",
			},
			mockPostResponse: MockHTTPResponse(http.StatusCreated, ""),
			mockGetResponse:  MockHTTPResponse(http.StatusOK, ApplicationResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
		},
		{
			name: "error_post_request_failed",
			createApplication: &applicationsmodels.IdsecPCloudCreateApplication{
				AppID: "app-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name: "error_non_201_status",
			createApplication: &applicationsmodels.IdsecPCloudCreateApplication{
				AppID: "app-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusBadRequest, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
			service.doGet = MockGetFunc(tt.mockGetResponse, nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.Create(tt.createApplication)

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
				t.Errorf("Expected application result, got nil")
			}
		})
	}
}

func TestApplication(t *testing.T) {
	tests := []struct {
		name            string
		getApplication  *applicationsmodels.IdsecPCloudGetApplication
		mockGetResponse *http.Response
		mockGetError    error
		expectedAppID   string
		expectedError   bool
	}{
		{
			name: "success_get_application",
			getApplication: &applicationsmodels.IdsecPCloudGetApplication{
				AppID: "app-123",
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, ApplicationResponseJSON),
			mockGetError:    nil,
			expectedAppID:   "app-123",
			expectedError:   false,
		},
		{
			name: "error_get_request_failed",
			getApplication: &applicationsmodels.IdsecPCloudGetApplication{
				AppID: "app-123",
			},
			mockGetResponse: nil,
			mockGetError:    errors.New("network error"),
			expectedError:   true,
		},
		{
			name: "error_non_200_status",
			getApplication: &applicationsmodels.IdsecPCloudGetApplication{
				AppID: "app-123",
			},
			mockGetResponse: MockHTTPResponse(http.StatusNotFound, ErrorResponseJSON),
			mockGetError:    nil,
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockGetResponse, tt.mockGetError)

			result, err := service.Get(tt.getApplication)

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

			if result.AppID != tt.expectedAppID {
				t.Errorf("Expected app ID %s, got %s", tt.expectedAppID, result.AppID)
			}
		})
	}
}

func TestDeleteApplication(t *testing.T) {
	tests := []struct {
		name              string
		deleteApplication *applicationsmodels.IdsecPCloudDeleteApplication
		mockDeleteResp    *http.Response
		mockDeleteError   error
		expectedError     bool
	}{
		{
			name: "success_delete_application",
			deleteApplication: &applicationsmodels.IdsecPCloudDeleteApplication{
				AppID: "app-123",
			},
			mockDeleteResp:  MockHTTPResponse(http.StatusOK, ""),
			mockDeleteError: nil,
			expectedError:   false,
		},
		{
			name: "error_delete_request_failed",
			deleteApplication: &applicationsmodels.IdsecPCloudDeleteApplication{
				AppID: "app-123",
			},
			mockDeleteResp:  nil,
			mockDeleteError: errors.New("network error"),
			expectedError:   true,
		},
		{
			name: "error_non_200_status",
			deleteApplication: &applicationsmodels.IdsecPCloudDeleteApplication{
				AppID: "app-123",
			},
			mockDeleteResp:  MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockDeleteError: nil,
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doDelete = MockDeleteFunc(tt.mockDeleteResp, tt.mockDeleteError)

			err = service.Delete(tt.deleteApplication)

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

func TestListApplications(t *testing.T) {
	tests := []struct {
		name            string
		mockGetResponse *http.Response
		mockGetError    error
		expectedCount   int
		expectedError   bool
	}{
		{
			name:            "success_list_applications",
			mockGetResponse: MockHTTPResponse(http.StatusOK, ApplicationsListResponseJSON),
			mockGetError:    nil,
			expectedCount:   2,
			expectedError:   false,
		},
		{
			name:            "error_get_request_failed",
			mockGetResponse: nil,
			mockGetError:    errors.New("network error"),
			expectedError:   true,
		},
		{
			name:            "error_non_200_status",
			mockGetResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockGetError:    nil,
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockGetResponse, tt.mockGetError)

			result, err := service.List()

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

			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d applications, got %d", tt.expectedCount, len(result))
			}
		})
	}
}

func TestListApplicationsBy(t *testing.T) {
	enabledFilter := true
	tests := []struct {
		name            string
		filter          *applicationsmodels.IdsecPCloudApplicationsFilter
		mockGetResponse *http.Response
		mockGetError    error
		expectedCount   int
		expectedError   bool
	}{
		{
			name: "success_filter_by_location",
			filter: &applicationsmodels.IdsecPCloudApplicationsFilter{
				Location: "\\Location1",
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, ApplicationsListResponseJSON),
			mockGetError:    nil,
			expectedCount:   1,
			expectedError:   false,
		},
		{
			name: "success_filter_by_enabled",
			filter: &applicationsmodels.IdsecPCloudApplicationsFilter{
				OnlyEnabled: &enabledFilter,
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, ApplicationsListResponseJSON),
			mockGetError:    nil,
			expectedCount:   1,
			expectedError:   false,
		},
		{
			name: "success_filter_by_business_owner_email",
			filter: &applicationsmodels.IdsecPCloudApplicationsFilter{
				BusinessOwnerEmail: "john.doe@example.com",
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, ApplicationsListResponseJSON),
			mockGetError:    nil,
			expectedCount:   1,
			expectedError:   false,
		},
		{
			name:            "error_list_applications_failed",
			filter:          &applicationsmodels.IdsecPCloudApplicationsFilter{},
			mockGetResponse: nil,
			mockGetError:    errors.New("network error"),
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockGetResponse, tt.mockGetError)

			result, err := service.ListBy(tt.filter)

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

			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d applications, got %d", tt.expectedCount, len(result))
			}
		})
	}
}

func TestCreateApplicationAuthMethod(t *testing.T) {
	tests := []struct {
		name             string
		createAuthMethod *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod
		mockPostResponse *http.Response
		mockGetResponse  *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecPCloudApplicationsService)
	}{
		{
			name: "success_create_hash_auth_method",
			createAuthMethod: &applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{
				AppID:     "app-123",
				AuthType:  applicationsmodels.ApplicationAuthMethodHash,
				AuthValue: "test-hash",
				Comment:   "Test hash method",
			},
			mockPostResponse: MockHTTPResponse(http.StatusCreated, ""),
			mockGetResponse:  MockHTTPResponse(http.StatusOK, AuthMethodResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecPCloudApplicationsService) {
				service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusCreated, ""), nil
				}
				service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, AuthMethodResponseJSON), nil
				}
			},
		},
		{
			name: "success_create_path_auth_method",
			createAuthMethod: &applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{
				AppID:                "app-123",
				AuthType:             applicationsmodels.ApplicationAuthMethodPath,
				AuthValue:            "/test/path",
				IsFolder:             BoolPtr(true),
				AllowInternalScripts: BoolPtr(false),
			},
			mockPostResponse: MockHTTPResponse(http.StatusCreated, ""),
			mockGetResponse:  MockHTTPResponse(http.StatusOK, AuthMethodResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecPCloudApplicationsService) {
				service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusCreated, ""), nil
				}
				service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
					// Return auth method with matching type
					pathAuthMethodJSON := `{
						"authentication": [
							{
								"auth_i_d": "auth-123",
								"auth_type": "path",
								"auth_value": "/test/path",
								"is_folder": true,
								"allow_internal_scripts": false
							}
						]
					}`
					return MockHTTPResponse(http.StatusOK, pathAuthMethodJSON), nil
				}
			},
		},
		{
			name: "error_hash_auth_missing_value",
			createAuthMethod: &applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{
				AppID:    "app-123",
				AuthType: applicationsmodels.ApplicationAuthMethodHash,
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_unsupported_auth_type",
			createAuthMethod: &applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{
				AppID:    "app-123",
				AuthType: "unsupported",
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_post_request_failed",
			createAuthMethod: &applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{
				AppID:     "app-123",
				AuthType:  applicationsmodels.ApplicationAuthMethodHash,
				AuthValue: "test-hash",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			} else {
				service.doPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
				service.doGet = MockGetFunc(tt.mockGetResponse, nil)
			}

			result, err := service.CreateAuthMethod(tt.createAuthMethod)

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
				t.Errorf("Expected auth method result, got nil")
			}
		})
	}
}

func TestGetAuthMethod(t *testing.T) {
	tests := []struct {
		name            string
		getAuthMethod   *applicationsmodels.IdsecPCloudGetApplicationAuthMethod
		mockGetResponse *http.Response
		mockGetError    error
		expectedAuthID  string
		expectedError   bool
	}{
		{
			name: "success_get_auth_method",
			getAuthMethod: &applicationsmodels.IdsecPCloudGetApplicationAuthMethod{
				AppID:  "app-123",
				AuthID: "auth-123",
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, AuthMethodResponseJSON),
			mockGetError:    nil,
			expectedAuthID:  "auth-123",
			expectedError:   false,
		},
		{
			name: "error_auth_method_not_found",
			getAuthMethod: &applicationsmodels.IdsecPCloudGetApplicationAuthMethod{
				AppID:  "app-123",
				AuthID: "nonexistent",
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, EmptyAuthMethodsResponseJSON),
			mockGetError:    nil,
			expectedError:   true,
		},
		{
			name: "error_get_request_failed",
			getAuthMethod: &applicationsmodels.IdsecPCloudGetApplicationAuthMethod{
				AppID:  "app-123",
				AuthID: "auth-123",
			},
			mockGetResponse: nil,
			mockGetError:    errors.New("network error"),
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockGetResponse, tt.mockGetError)

			result, err := service.GetAuthMethod(tt.getAuthMethod)

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

			if result.AuthID != tt.expectedAuthID {
				t.Errorf("Expected auth ID %s, got %s", tt.expectedAuthID, result.AuthID)
			}
		})
	}
}

func TestDeleteApplicationAuthMethod(t *testing.T) {
	tests := []struct {
		name             string
		deleteAuthMethod *applicationsmodels.IdsecPCloudDeleteApplicationAuthMethod
		mockDeleteResp   *http.Response
		mockDeleteError  error
		expectedError    bool
	}{
		{
			name: "success_delete_auth_method",
			deleteAuthMethod: &applicationsmodels.IdsecPCloudDeleteApplicationAuthMethod{
				AppID:  "app-123",
				AuthID: "auth-123",
			},
			mockDeleteResp:  MockHTTPResponse(http.StatusOK, ""),
			mockDeleteError: nil,
			expectedError:   false,
		},
		{
			name: "error_delete_request_failed",
			deleteAuthMethod: &applicationsmodels.IdsecPCloudDeleteApplicationAuthMethod{
				AppID:  "app-123",
				AuthID: "auth-123",
			},
			mockDeleteResp:  nil,
			mockDeleteError: errors.New("network error"),
			expectedError:   true,
		},
		{
			name: "error_non_200_status",
			deleteAuthMethod: &applicationsmodels.IdsecPCloudDeleteApplicationAuthMethod{
				AppID:  "app-123",
				AuthID: "auth-123",
			},
			mockDeleteResp:  MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockDeleteError: nil,
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doDelete = MockDeleteFunc(tt.mockDeleteResp, tt.mockDeleteError)

			err = service.DeleteAuthMethod(tt.deleteAuthMethod)

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

func TestListApplicationAuthMethods(t *testing.T) {
	tests := []struct {
		name            string
		listAuthMethods *applicationsmodels.IdsecPCloudListApplicationAuthMethods
		mockGetResponse *http.Response
		mockGetError    error
		expectedCount   int
		expectedError   bool
	}{
		{
			name: "success_list_auth_methods",
			listAuthMethods: &applicationsmodels.IdsecPCloudListApplicationAuthMethods{
				AppID: "app-123",
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, AuthMethodsListResponseJSON),
			mockGetError:    nil,
			expectedCount:   2,
			expectedError:   false,
		},
		{
			name: "success_empty_auth_methods",
			listAuthMethods: &applicationsmodels.IdsecPCloudListApplicationAuthMethods{
				AppID: "app-456",
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, EmptyAuthMethodsResponseJSON),
			mockGetError:    nil,
			expectedCount:   0,
			expectedError:   false,
		},
		{
			name: "error_get_request_failed",
			listAuthMethods: &applicationsmodels.IdsecPCloudListApplicationAuthMethods{
				AppID: "app-123",
			},
			mockGetResponse: nil,
			mockGetError:    errors.New("network error"),
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockGetResponse, tt.mockGetError)

			result, err := service.ListAuthMethods(tt.listAuthMethods)

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

			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d auth methods, got %d", tt.expectedCount, len(result))
			}
		})
	}
}

func TestListApplicationAuthMethodsBy(t *testing.T) {
	tests := []struct {
		name            string
		filter          *applicationsmodels.IdsecPCloudApplicationAuthMethodsFilter
		mockGetResponse *http.Response
		mockGetError    error
		expectedCount   int
		expectedError   bool
	}{
		{
			name: "success_filter_by_auth_types",
			filter: &applicationsmodels.IdsecPCloudApplicationAuthMethodsFilter{
				AppID:     "app-123",
				AuthTypes: []string{applicationsmodels.ApplicationAuthMethodHash},
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, AuthMethodsListResponseJSON),
			mockGetError:    nil,
			expectedCount:   1,
			expectedError:   false,
		},
		{
			name: "success_no_filter",
			filter: &applicationsmodels.IdsecPCloudApplicationAuthMethodsFilter{
				AppID: "app-123",
			},
			mockGetResponse: MockHTTPResponse(http.StatusOK, AuthMethodsListResponseJSON),
			mockGetError:    nil,
			expectedCount:   2,
			expectedError:   false,
		},
		{
			name: "error_list_failed",
			filter: &applicationsmodels.IdsecPCloudApplicationAuthMethodsFilter{
				AppID: "app-123",
			},
			mockGetResponse: nil,
			mockGetError:    errors.New("network error"),
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doGet = MockGetFunc(tt.mockGetResponse, tt.mockGetError)

			result, err := service.ListAuthMethodsBy(tt.filter)

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

			if len(result) != tt.expectedCount {
				t.Errorf("Expected %d auth methods, got %d", tt.expectedCount, len(result))
			}
		})
	}
}

func TestApplicationsStats(t *testing.T) {
	tests := []struct {
		name                  string
		mockGetResponse       *http.Response
		mockGetError          error
		expectedAppsCount     int
		expectedDisabledCount int
		expectedError         bool
	}{
		{
			name:                  "success_get_stats",
			mockGetResponse:       MockHTTPResponse(http.StatusOK, ApplicationsListResponseJSON),
			mockGetError:          nil,
			expectedAppsCount:     2,
			expectedDisabledCount: 1,
			expectedError:         false,
		},
		{
			name:            "error_list_applications_failed",
			mockGetResponse: nil,
			mockGetError:    errors.New("network error"),
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				// First call is ListApplications, second is ListApplicationAuthMethods
				if tt.mockGetError != nil {
					return nil, tt.mockGetError
				}
				// Return applications list first, then empty auth methods
				if path == applicationsURL {
					return MockHTTPResponse(http.StatusOK, ApplicationsListResponseJSON), nil
				}
				return MockHTTPResponse(http.StatusOK, EmptyAuthMethodsResponseJSON), nil
			}

			result, err := service.Stats()

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

			if result.ApplicationsCount != tt.expectedAppsCount {
				t.Errorf("Expected %d applications, got %d", tt.expectedAppsCount, result.ApplicationsCount)
			}

			if len(result.DisabledApps) != tt.expectedDisabledCount {
				t.Errorf("Expected %d disabled apps, got %d", tt.expectedDisabledCount, len(result.DisabledApps))
			}
		})
	}
}

func TestServiceConfig(t *testing.T) {
	tests := []struct {
		name          string
		expectedError bool
	}{
		{
			name:          "success_get_service_config",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecPCloudApplicationsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecPCloudApplicationsService: %v", err)
			}

			result := service.ServiceConfig()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if !reflect.DeepEqual(result, ServiceConfig) {
				t.Errorf("Expected service config %+v, got %+v", ServiceConfig, result)
			}
		})
	}
}
