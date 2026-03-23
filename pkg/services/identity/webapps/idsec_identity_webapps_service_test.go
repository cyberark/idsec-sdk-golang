package webapps

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	webappsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/webapps/models"
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

// MockGetFunc creates a mock function for GET operations that returns the provided response.
func MockGetFunc(response *http.Response, err error) func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	return func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
		return response, err
	}
}

// MockISPAuth creates a mock IdsecISPAuth for testing.
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

// strPtr is a helper function to create a pointer to a string value.
func strPtr(s string) *string {
	return &s
}

// boolPtr is a helper function to create a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}

// Sample JSON responses for testing
const (
	ImportWebappResponseJSON = `{
		"success": true,
		"Result": [
			{
				"_RowKey": "webapp-123",
				"Name": "TestWebapp",
				"AppType": "Generic"
			}
		]
	}`

	ImportWebappFailureResponseJSON = `{
		"success": false,
		"error": "import failed"
	}`

	GetWebappResponseJSON = `{
		"success": true,
		"Result": {
			"_RowKey": "webapp-123",
			"Name": "TestWebapp",
			"DisplayName": "Test Webapp",
			"Description": "A test webapp",
			"WebAppType": "SAML",
			"WebAppTypeDisplayName": "SAML",
			"AppTypeDisplayName": "SAML App",
			"TemplateName": "saml-template",
			"State": "Active",
			"ServiceName": "TestService"
		}
	}`

	GetWebappNotFoundResponseJSON = `{
		"success": true,
		"Result": null
	}`

	UpdateWebappResponseJSON = `{
		"success": true
	}`

	UpdateWebappFailureResponseJSON = `{
		"success": false,
		"error": "update failed"
	}`

	DeleteWebappResponseJSON = `{
		"success": true
	}`

	DeleteWebappFailureResponseJSON = `{
		"success": false,
		"error": "delete failed"
	}`

	GetAppIDByNameResponseJSON = `{
		"success": true,
		"Result": "webapp-123"
	}`

	GetAppIDByNameFailureResponseJSON = `{
		"success": false,
		"error": "app not found"
	}`

	ListWebappsResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"ID": "webapp-1",
						"Name": "Webapp One",
						"DisplayName": "Webapp One Display",
						"Description": "First webapp",
						"WebAppType": "SAML",
						"WebAppTypeDisplayName": "SAML",
						"AppTypeDisplayName": "SAML App",
						"TemplateName": "saml-template",
						"State": "Active"
					}
				},
				{
					"Row": {
						"ID": "webapp-2",
						"Name": "Webapp Two",
						"DisplayName": "Webapp Two Display",
						"Description": "Second webapp",
						"WebAppType": "OAuth",
						"WebAppTypeDisplayName": "OAuth",
						"AppTypeDisplayName": "OAuth App",
						"TemplateName": "oauth-template",
						"State": "Active"
					}
				}
			]
		}
	}`

	ListWebappsEmptyResponseJSON = `{
		"success": true,
		"Result": {
			"Results": []
		}
	}`

	GetPermissionsResponseJSON = `{
		"success": true,
		"Result": [
			{
				"PrincipalName": "john.doe@example.com",
				"Principal": "user-principal-id",
				"PrincipalType": "User",
				"Type": "User",
				"Grant": 28
			}
		]
	}`

	GetPermissionsEmptyResponseJSON = `{
		"success": true,
		"Result": []
	}`

	SetPermissionsResponseJSON = `{
		"success": true
	}`

	SetPermissionsFailureResponseJSON = `{
		"success": false,
		"error": "set permissions failed"
	}`

	ListTemplatesResponseJSON = `{
		"success": true,
		"Result": {
			"AppTemplates": {
				"Results": [
					{
						"Row": {
							"ID": "template-1",
							"Name": "saml-template",
							"DisplayName": "SAML Template",
							"AppTypeDisplayName": "SAML App",
							"Description": "A SAML template",
							"AppType": "SAML",
							"WebAppTypeDisplayName": "SAML"
						}
					},
					{
						"Row": {
							"ID": "template-2",
							"Name": "oauth-template",
							"DisplayName": "OAuth Template",
							"AppTypeDisplayName": "OAuth App",
							"Description": "An OAuth template",
							"AppType": "OAuth",
							"WebAppTypeDisplayName": "OAuth"
						}
					}
				]
			}
		}
	}`

	ListTemplatesEmptyResponseJSON = `{
		"success": true,
		"Result": {
			"AppTemplates": {
				"Results": []
			}
		}
	}`

	ListCustomTemplatesResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"ID": "custom-template-1",
						"Name": "custom-saml-template",
						"DisplayName": "Custom SAML Template",
						"AppTypeDisplayName": "Custom SAML App",
						"Description": "A custom SAML template",
						"AppType": "SAML",
						"WebAppTypeDisplayName": "Custom SAML"
					}
				}
			]
		}
	}`

	ListCustomTemplatesEmptyResponseJSON = `{
		"success": true,
		"Result": {
			"Results": []
		}
	}`

	ListTemplatesCategoriesResponseJSON = `{
		"success": true,
		"Result": {
			"Categories": [
				"SAML",
				"OAuth",
				"Generic"
			]
		}
	}`

	ListTemplatesCategoriesEmptyResponseJSON = `{
		"success": true,
		"Result": {
			"Categories": []
		}
	}`

	ErrorResponseJSON = `{
		"success": false,
		"error": "operation failed"
	}`
)

func TestImport(t *testing.T) {
	tests := []struct {
		name          string
		importWebapp  *webappsmodels.IdsecIdentityImportWebapp
		expectedError bool
		setupMock     func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_import_basic_webapp",
			importWebapp: &webappsmodels.IdsecIdentityImportWebapp{
				TemplateName: "saml-template",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == importAppFromTemplateURL {
						return MockHTTPResponse(http.StatusOK, ImportWebappResponseJSON), nil
					}
					// GetApplication call
					return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
				}
			},
		},
		{
			name: "success_import_webapp_with_name_update",
			importWebapp: &webappsmodels.IdsecIdentityImportWebapp{
				TemplateName: "saml-template",
				WebappName:   strPtr("MyCustomWebapp"),
				Description:  strPtr("My custom description"),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					switch path {
					case importAppFromTemplateURL:
						return MockHTTPResponse(http.StatusOK, ImportWebappResponseJSON), nil
					case getApplicationURL:
						return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
					case updateApplicationURL:
						return MockHTTPResponse(http.StatusOK, UpdateWebappResponseJSON), nil
					default:
						return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
					}
				}
			},
		},
		{
			name: "error_http_request_failed",
			importWebapp: &webappsmodels.IdsecIdentityImportWebapp{
				TemplateName: "saml-template",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			importWebapp: &webappsmodels.IdsecIdentityImportWebapp{
				TemplateName: "saml-template",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
		{
			name: "error_success_false",
			importWebapp: &webappsmodels.IdsecIdentityImportWebapp{
				TemplateName: "saml-template",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ImportWebappFailureResponseJSON), nil
				}
			},
		},
		{
			name: "error_invalid_result_format",
			importWebapp: &webappsmodels.IdsecIdentityImportWebapp{
				TemplateName: "saml-template",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, `{"success": true, "Result": "not-an-array"}`), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.ImportWebapp(tt.importWebapp)

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
				t.Errorf("Expected result, got nil")
			}
		})
	}
}

func TestGet(t *testing.T) {
	tests := []struct {
		name           string
		getWebapp      *webappsmodels.IdsecIdentityGetWebapp
		expectedError  bool
		expectedWebapp *webappsmodels.IdsecIdentityWebapp
		setupMock      func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_get_webapp_by_id",
			getWebapp: &webappsmodels.IdsecIdentityGetWebapp{
				WebappID: "webapp-123",
			},
			expectedError: false,
			expectedWebapp: &webappsmodels.IdsecIdentityWebapp{
				WebappID:   "webapp-123",
				WebappName: "TestWebapp",
			},
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil)
			},
		},
		{
			name: "success_get_webapp_by_name",
			getWebapp: &webappsmodels.IdsecIdentityGetWebapp{
				WebappName: "TestWebapp",
			},
			expectedError: false,
			expectedWebapp: &webappsmodels.IdsecIdentityWebapp{
				WebappID:   "webapp-123",
				WebappName: "TestWebapp",
			},
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == getApplicationIDByNameURL {
						return MockHTTPResponse(http.StatusOK, GetAppIDByNameResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
				}
			},
		},
		{
			name:          "error_no_id_or_name",
			getWebapp:     &webappsmodels.IdsecIdentityGetWebapp{},
			expectedError: true,
		},
		{
			name: "error_http_request_failed",
			getWebapp: &webappsmodels.IdsecIdentityGetWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
		{
			name: "error_non_200_status",
			getWebapp: &webappsmodels.IdsecIdentityGetWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil)
			},
		},
		{
			name: "error_success_false",
			getWebapp: &webappsmodels.IdsecIdentityGetWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ErrorResponseJSON), nil)
			},
		},
		{
			name: "error_result_not_map",
			getWebapp: &webappsmodels.IdsecIdentityGetWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, GetWebappNotFoundResponseJSON), nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.Webapp(tt.getWebapp)

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
				t.Errorf("Expected result, got nil")
				return
			}

			if tt.expectedWebapp != nil {
				if result.WebappID != tt.expectedWebapp.WebappID {
					t.Errorf("Expected webapp ID %s, got %s", tt.expectedWebapp.WebappID, result.WebappID)
				}
				if result.WebappName != tt.expectedWebapp.WebappName {
					t.Errorf("Expected webapp name %s, got %s", tt.expectedWebapp.WebappName, result.WebappName)
				}
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	tests := []struct {
		name          string
		updateWebapp  *webappsmodels.IdsecIdentityUpdateWebapp
		expectedError bool
		setupMock     func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_update_webapp_name",
			updateWebapp: &webappsmodels.IdsecIdentityUpdateWebapp{
				WebappID:   "webapp-123",
				WebappName: strPtr("UpdatedWebapp"),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					switch path {
					case getApplicationURL:
						return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
					case updateApplicationURL:
						return MockHTTPResponse(http.StatusOK, UpdateWebappResponseJSON), nil
					default:
						return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
					}
				}
			},
		},
		{
			name: "success_update_webapp_description",
			updateWebapp: &webappsmodels.IdsecIdentityUpdateWebapp{
				WebappID:    "webapp-123",
				Description: strPtr("Updated description"),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					switch path {
					case getApplicationURL:
						return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
					case updateApplicationURL:
						return MockHTTPResponse(http.StatusOK, UpdateWebappResponseJSON), nil
					default:
						return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
					}
				}
			},
		},
		{
			name: "error_get_webapp_failed",
			updateWebapp: &webappsmodels.IdsecIdentityUpdateWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == getApplicationURL {
						return nil, errors.New("failed to get webapp")
					}
					return MockHTTPResponse(http.StatusOK, UpdateWebappResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			updateWebapp: &webappsmodels.IdsecIdentityUpdateWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == getApplicationURL {
						return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
					}
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			updateWebapp: &webappsmodels.IdsecIdentityUpdateWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == getApplicationURL {
						return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
		{
			name: "error_success_false",
			updateWebapp: &webappsmodels.IdsecIdentityUpdateWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == getApplicationURL {
						return MockHTTPResponse(http.StatusOK, GetWebappResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, UpdateWebappFailureResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UpdateWebapp(tt.updateWebapp)

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
				t.Errorf("Expected result, got nil")
			}
		})
	}
}

func TestDelete(t *testing.T) {
	tests := []struct {
		name          string
		deleteWebapp  *webappsmodels.IdsecIdentityDeleteWebapp
		expectedError bool
		setupMock     func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_delete_by_id",
			deleteWebapp: &webappsmodels.IdsecIdentityDeleteWebapp{
				WebappID: "webapp-123",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, DeleteWebappResponseJSON), nil)
			},
		},
		{
			name: "success_delete_by_name",
			deleteWebapp: &webappsmodels.IdsecIdentityDeleteWebapp{
				WebappName: "TestWebapp",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == getApplicationIDByNameURL {
						return MockHTTPResponse(http.StatusOK, GetAppIDByNameResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, DeleteWebappResponseJSON), nil
				}
			},
		},
		{
			name:          "error_no_id_or_name",
			deleteWebapp:  &webappsmodels.IdsecIdentityDeleteWebapp{},
			expectedError: true,
		},
		{
			name: "error_get_id_by_name_failed",
			deleteWebapp: &webappsmodels.IdsecIdentityDeleteWebapp{
				WebappName: "UnknownWebapp",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == getApplicationIDByNameURL {
						return MockHTTPResponse(http.StatusOK, GetAppIDByNameFailureResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, DeleteWebappResponseJSON), nil
				}
				service.DoRedrockQueryPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListWebappsEmptyResponseJSON), nil)
			},
		},
		{
			name: "error_http_request_failed",
			deleteWebapp: &webappsmodels.IdsecIdentityDeleteWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
		{
			name: "error_non_200_status",
			deleteWebapp: &webappsmodels.IdsecIdentityDeleteWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil)
			},
		},
		{
			name: "error_success_false",
			deleteWebapp: &webappsmodels.IdsecIdentityDeleteWebapp{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, DeleteWebappFailureResponseJSON), nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			err = service.DeleteWebapp(tt.deleteWebapp)

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

func TestList(t *testing.T) {
	tests := []struct {
		name              string
		expectedError     bool
		expectedItemCount int
		setupMock         func(service *IdsecIdentityWebappsService)
	}{
		{
			name:              "success_list_webapps",
			expectedError:     false,
			expectedItemCount: 2,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoRedrockQueryPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListWebappsResponseJSON), nil)
			},
		},
		{
			name:              "success_list_webapps_empty",
			expectedError:     false,
			expectedItemCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoRedrockQueryPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListWebappsEmptyResponseJSON), nil)
			},
		},
		{
			name:              "error_http_request_failed_returns_empty_channel",
			expectedError:     false, // list returns channel, errors are logged internally
			expectedItemCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoRedrockQueryPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			pages, err := service.ListWebapps()

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

			totalItems := 0
			for page := range pages {
				totalItems += len(page.Items)
			}

			if totalItems != tt.expectedItemCount {
				t.Errorf("Expected %d items, got %d", tt.expectedItemCount, totalItems)
			}
		})
	}
}

func TestListBy(t *testing.T) {
	tests := []struct {
		name              string
		filters           *webappsmodels.IdsecIdentityWebappsFilters
		expectedError     bool
		expectedItemCount int
		setupMock         func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_list_by_with_search",
			filters: &webappsmodels.IdsecIdentityWebappsFilters{
				Search:   "TestWebapp",
				PageSize: 100,
				Limit:    100,
			},
			expectedError:     false,
			expectedItemCount: 2,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoRedrockQueryPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListWebappsResponseJSON), nil)
			},
		},
		{
			name: "success_list_by_empty_result",
			filters: &webappsmodels.IdsecIdentityWebappsFilters{
				Search: "NonExistentWebapp",
			},
			expectedError:     false,
			expectedItemCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoRedrockQueryPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListWebappsEmptyResponseJSON), nil)
			},
		},
		{
			name:              "success_list_by_default_values",
			filters:           &webappsmodels.IdsecIdentityWebappsFilters{},
			expectedItemCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoRedrockQueryPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListWebappsEmptyResponseJSON), nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			pages, err := service.ListWebappsBy(tt.filters)

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

			totalItems := 0
			for page := range pages {
				totalItems += len(page.Items)
			}

			if totalItems != tt.expectedItemCount {
				t.Errorf("Expected %d items, got %d", tt.expectedItemCount, totalItems)
			}
		})
	}
}

func TestGetPermissions(t *testing.T) {
	tests := []struct {
		name           string
		getPermissions *webappsmodels.IdsecIdentityGetWebappPermissions
		expectedError  bool
		setupMock      func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_get_permissions_by_id",
			getPermissions: &webappsmodels.IdsecIdentityGetWebappPermissions{
				WebappID: "webapp-123",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, GetPermissionsResponseJSON), nil)
			},
		},
		{
			name: "success_get_permissions_by_name",
			getPermissions: &webappsmodels.IdsecIdentityGetWebappPermissions{
				WebappName: "TestWebapp",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == getApplicationIDByNameURL {
						return MockHTTPResponse(http.StatusOK, GetAppIDByNameResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, GetPermissionsResponseJSON), nil
				}
			},
		},
		{
			name: "success_get_permissions_empty",
			getPermissions: &webappsmodels.IdsecIdentityGetWebappPermissions{
				WebappID: "webapp-123",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, GetPermissionsEmptyResponseJSON), nil)
			},
		},
		{
			name:           "error_no_id_or_name",
			getPermissions: &webappsmodels.IdsecIdentityGetWebappPermissions{},
			expectedError:  true,
		},
		{
			name: "error_http_request_failed",
			getPermissions: &webappsmodels.IdsecIdentityGetWebappPermissions{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
		{
			name: "error_non_200_status",
			getPermissions: &webappsmodels.IdsecIdentityGetWebappPermissions{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil)
			},
		},
		{
			name: "error_success_false",
			getPermissions: &webappsmodels.IdsecIdentityGetWebappPermissions{
				WebappID: "webapp-123",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ErrorResponseJSON), nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.WebappPermissions(tt.getPermissions)

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
				t.Errorf("Expected result, got nil")
			}
		})
	}
}

func TestSetPermissions(t *testing.T) {
	tests := []struct {
		name           string
		setPermissions *webappsmodels.IdsecIdentitySetWebappPermissions
		expectedError  bool
		setupMock      func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_set_permissions_with_principal_id",
			setPermissions: &webappsmodels.IdsecIdentitySetWebappPermissions{
				WebappID: "webapp-123",
				Grants: []webappsmodels.IdsecIdentityWebappGrant{
					{
						Principal:     "john.doe@example.com",
						PrincipalType: "User",
						Rights:        []string{"View"},
						PrincipalId:   strPtr("user-principal-id"),
					},
				},
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == setApplicationPermissionsURL {
						return MockHTTPResponse(http.StatusOK, SetPermissionsResponseJSON), nil
					}
					// GetPermissions call
					return MockHTTPResponse(http.StatusOK, GetPermissionsResponseJSON), nil
				}
			},
		},
		{
			name: "success_set_permissions_no_grants",
			setPermissions: &webappsmodels.IdsecIdentitySetWebappPermissions{
				WebappID: "webapp-123",
				Grants:   []webappsmodels.IdsecIdentityWebappGrant{},
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == setApplicationPermissionsURL {
						return MockHTTPResponse(http.StatusOK, SetPermissionsResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, GetPermissionsEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "success_set_permissions_by_name",
			setPermissions: &webappsmodels.IdsecIdentitySetWebappPermissions{
				WebappName: "TestWebapp",
				Grants:     []webappsmodels.IdsecIdentityWebappGrant{},
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == getApplicationIDByNameURL {
						return MockHTTPResponse(http.StatusOK, GetAppIDByNameResponseJSON), nil
					}
					if path == setApplicationPermissionsURL {
						return MockHTTPResponse(http.StatusOK, SetPermissionsResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, GetPermissionsEmptyResponseJSON), nil
				}
			},
		},
		{
			name: "error_no_id_or_name",
			setPermissions: &webappsmodels.IdsecIdentitySetWebappPermissions{
				Grants: []webappsmodels.IdsecIdentityWebappGrant{},
			},
			expectedError: true,
		},
		{
			name: "error_set_permissions_http_failed",
			setPermissions: &webappsmodels.IdsecIdentitySetWebappPermissions{
				WebappID: "webapp-123",
				Grants: []webappsmodels.IdsecIdentityWebappGrant{
					{
						Principal:     "john.doe@example.com",
						PrincipalType: "User",
						Rights:        []string{"View"},
						PrincipalId:   strPtr("user-principal-id"),
					},
				},
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
		{
			name: "error_set_permissions_non_200",
			setPermissions: &webappsmodels.IdsecIdentitySetWebappPermissions{
				WebappID: "webapp-123",
				Grants: []webappsmodels.IdsecIdentityWebappGrant{
					{
						Principal:     "john.doe@example.com",
						PrincipalType: "User",
						Rights:        []string{"View"},
						PrincipalId:   strPtr("user-principal-id"),
					},
				},
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil)
			},
		},
		{
			name: "error_set_permissions_success_false",
			setPermissions: &webappsmodels.IdsecIdentitySetWebappPermissions{
				WebappID: "webapp-123",
				Grants: []webappsmodels.IdsecIdentityWebappGrant{
					{
						Principal:     "john.doe@example.com",
						PrincipalType: "User",
						Rights:        []string{"View"},
						PrincipalId:   strPtr("user-principal-id"),
					},
				},
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, SetPermissionsFailureResponseJSON), nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.SetWebappPermissions(tt.setPermissions)

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
				t.Errorf("Expected result, got nil")
			}
		})
	}
}

func TestListTemplates(t *testing.T) {
	tests := []struct {
		name              string
		expectedError     bool
		expectedItemCount int
		setupMock         func(service *IdsecIdentityWebappsService)
	}{
		{
			name:              "success_list_templates",
			expectedError:     false,
			expectedItemCount: 2,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListTemplatesResponseJSON), nil)
			},
		},
		{
			name:              "success_list_templates_empty",
			expectedError:     false,
			expectedItemCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListTemplatesEmptyResponseJSON), nil)
			},
		},
		{
			name:              "error_http_request_failed_returns_empty_channel",
			expectedError:     false, // list returns channel, errors are logged internally
			expectedItemCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			pages, err := service.ListWebappTemplates()

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

			totalItems := 0
			for page := range pages {
				totalItems += len(page.Items)
			}

			if totalItems != tt.expectedItemCount {
				t.Errorf("Expected %d items, got %d", tt.expectedItemCount, totalItems)
			}
		})
	}
}

func TestListTemplatesBy(t *testing.T) {
	tests := []struct {
		name              string
		filters           *webappsmodels.IdsecIdentityWebappsTemplatesFilters
		expectedError     bool
		expectedItemCount int
		setupMock         func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_list_templates_by_search",
			filters: &webappsmodels.IdsecIdentityWebappsTemplatesFilters{
				Search:   "saml",
				PageSize: 100,
				Limit:    100,
			},
			expectedError:     false,
			expectedItemCount: 2,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListTemplatesResponseJSON), nil)
			},
		},
		{
			name: "success_list_templates_by_empty_result",
			filters: &webappsmodels.IdsecIdentityWebappsTemplatesFilters{
				Search: "NonExistentTemplate",
			},
			expectedError:     false,
			expectedItemCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListTemplatesEmptyResponseJSON), nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			pages, err := service.ListWebappTemplatesBy(tt.filters)

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

			totalItems := 0
			for page := range pages {
				totalItems += len(page.Items)
			}

			if totalItems != tt.expectedItemCount {
				t.Errorf("Expected %d items, got %d", tt.expectedItemCount, totalItems)
			}
		})
	}
}

func TestListCustomTemplates(t *testing.T) {
	tests := []struct {
		name              string
		expectedError     bool
		expectedItemCount int
		setupMock         func(service *IdsecIdentityWebappsService)
	}{
		{
			name:              "success_list_custom_templates",
			expectedError:     false,
			expectedItemCount: 1,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListCustomTemplatesResponseJSON), nil)
			},
		},
		{
			name:              "success_list_custom_templates_empty",
			expectedError:     false,
			expectedItemCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListCustomTemplatesEmptyResponseJSON), nil)
			},
		},
		{
			name:          "error_http_request_failed",
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
		{
			name:          "error_non_200_status",
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil)
			},
		},
		{
			name:          "error_success_false",
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ErrorResponseJSON), nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.ListWebappCustomTemplates()

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
				t.Errorf("Expected result, got nil")
				return
			}

			if len(result.Templates) != tt.expectedItemCount {
				t.Errorf("Expected %d templates, got %d", tt.expectedItemCount, len(result.Templates))
			}
		})
	}
}

func TestListCustomTemplatesBy(t *testing.T) {
	tests := []struct {
		name              string
		filters           *webappsmodels.IdsecIdentityWebappsCustomTemplatesFilters
		expectedError     bool
		expectedItemCount int
		setupMock         func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_list_custom_templates_by_search_match",
			filters: &webappsmodels.IdsecIdentityWebappsCustomTemplatesFilters{
				Search: "custom-saml",
			},
			expectedError:     false,
			expectedItemCount: 1,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListCustomTemplatesResponseJSON), nil)
			},
		},
		{
			name: "success_list_custom_templates_by_search_no_match",
			filters: &webappsmodels.IdsecIdentityWebappsCustomTemplatesFilters{
				Search: "oauth-template",
			},
			expectedError:     false,
			expectedItemCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListCustomTemplatesResponseJSON), nil)
			},
		},
		{
			name:              "success_list_custom_templates_by_empty_search",
			filters:           &webappsmodels.IdsecIdentityWebappsCustomTemplatesFilters{},
			expectedError:     false,
			expectedItemCount: 1,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListCustomTemplatesResponseJSON), nil)
			},
		},
		{
			name: "error_list_custom_templates_failed",
			filters: &webappsmodels.IdsecIdentityWebappsCustomTemplatesFilters{
				Search: "something",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.ListWebappCustomTemplatesBy(tt.filters)

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
				t.Errorf("Expected result, got nil")
				return
			}

			if len(result.Templates) != tt.expectedItemCount {
				t.Errorf("Expected %d templates, got %d", tt.expectedItemCount, len(result.Templates))
			}
		})
	}
}

func TestListTemplatesCategories(t *testing.T) {
	tests := []struct {
		name                    string
		expectedError           bool
		expectedCategoriesCount int
		setupMock               func(service *IdsecIdentityWebappsService)
	}{
		{
			name:                    "success_list_categories",
			expectedError:           false,
			expectedCategoriesCount: 3,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListTemplatesCategoriesResponseJSON), nil)
			},
		},
		{
			name:                    "success_list_categories_empty",
			expectedError:           false,
			expectedCategoriesCount: 0,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListTemplatesCategoriesEmptyResponseJSON), nil)
			},
		},
		{
			name:          "error_http_request_failed",
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
		{
			name:          "error_non_200_status",
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil)
			},
		},
		{
			name:          "error_success_false",
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ErrorResponseJSON), nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.ListWebappTemplatesCategories()

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
				t.Errorf("Expected result, got nil")
				return
			}

			if len(result.Categories) != tt.expectedCategoriesCount {
				t.Errorf("Expected %d categories, got %d", tt.expectedCategoriesCount, len(result.Categories))
			}
		})
	}
}

func TestGetTemplate(t *testing.T) {
	tests := []struct {
		name          string
		getTemplate   *webappsmodels.IdsecIdentityGetWebappTemplate
		expectedError bool
		setupMock     func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_get_template_by_id",
			getTemplate: &webappsmodels.IdsecIdentityGetWebappTemplate{
				WebappTemplateID: "template-1",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListTemplatesResponseJSON), nil)
			},
		},
		{
			name: "success_get_template_by_name",
			getTemplate: &webappsmodels.IdsecIdentityGetWebappTemplate{
				WebappTemplateName: "saml-template",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListTemplatesResponseJSON), nil)
			},
		},
		{
			name:          "error_no_id_or_name",
			getTemplate:   &webappsmodels.IdsecIdentityGetWebappTemplate{},
			expectedError: true,
		},
		{
			name: "error_template_not_found",
			getTemplate: &webappsmodels.IdsecIdentityGetWebappTemplate{
				WebappTemplateID: "non-existent-template",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListTemplatesEmptyResponseJSON), nil)
			},
		},
		{
			name: "error_http_request_failed",
			getTemplate: &webappsmodels.IdsecIdentityGetWebappTemplate{
				WebappTemplateID: "template-1",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.WebappTemplate(tt.getTemplate)

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
				t.Errorf("Expected result, got nil")
			}
		})
	}
}

func TestGetCustomTemplate(t *testing.T) {
	tests := []struct {
		name              string
		getCustomTemplate *webappsmodels.IdsecIdentityGetWebappCustomTemplate
		expectedError     bool
		setupMock         func(service *IdsecIdentityWebappsService)
	}{
		{
			name: "success_get_custom_template_by_id",
			getCustomTemplate: &webappsmodels.IdsecIdentityGetWebappCustomTemplate{
				WebappTemplateID: "custom-template-1",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListCustomTemplatesResponseJSON), nil)
			},
		},
		{
			name: "success_get_custom_template_by_name",
			getCustomTemplate: &webappsmodels.IdsecIdentityGetWebappCustomTemplate{
				WebappTemplateName: "custom-saml-template",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListCustomTemplatesResponseJSON), nil)
			},
		},
		{
			name:              "error_no_id_or_name",
			getCustomTemplate: &webappsmodels.IdsecIdentityGetWebappCustomTemplate{},
			expectedError:     true,
		},
		{
			name: "error_custom_template_not_found",
			getCustomTemplate: &webappsmodels.IdsecIdentityGetWebappCustomTemplate{
				WebappTemplateID: "non-existent-custom-template",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListCustomTemplatesEmptyResponseJSON), nil)
			},
		},
		{
			name: "error_http_request_failed",
			getCustomTemplate: &webappsmodels.IdsecIdentityGetWebappCustomTemplate{
				WebappTemplateID: "custom-template-1",
			},
			expectedError: true,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoPost = MockPostFunc(nil, errors.New("network error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.WebappCustomTemplate(tt.getCustomTemplate)

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
				t.Errorf("Expected result, got nil")
			}
		})
	}
}

func TestStats(t *testing.T) {
	tests := []struct {
		name          string
		expectedError bool
		setupMock     func(service *IdsecIdentityWebappsService)
	}{
		{
			name:          "success_get_stats",
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoRedrockQueryPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListWebappsResponseJSON), nil)
			},
		},
		{
			name:          "success_get_stats_empty",
			expectedError: false,
			setupMock: func(service *IdsecIdentityWebappsService) {
				service.DoRedrockQueryPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListWebappsEmptyResponseJSON), nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityWebappsService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityWebappsService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.WebappStats()

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
				t.Errorf("Expected result, got nil")
			}
		})
	}
}
