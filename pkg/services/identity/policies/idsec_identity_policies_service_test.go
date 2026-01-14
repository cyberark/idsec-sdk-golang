package policies

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
	policymodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/policies/models"
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
	SavePolicyResponseJSON = `{
		"success": true,
		"Result": {
			"_RowKey": "policy-123"
		}
	}`

	SavePolicyFailureResponseJSON = `{
		"success": false
	}`

	GetPolicyResponseJSON = `{
		"success": true,
		"Result": {
			"RevStamp": "rev-123",
			"Description": "Test Policy Description",
			"Settings": {
				"AuthenticationEnabled": "true",
				"/Core/Authentication/AuthenticationRulesDefaultProfileId": "auth-profile-123"
			}
		}
	}`

	ListPolicyLinksResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"PolicySet": "/Policy/TestPolicy",
						"Description": "Test Policy Description",
						"LinkType": "Global",
						"Priority": 1
					}
				},
				{
					"Row": {
						"PolicySet": "/Policy/RolePolicy",
						"Description": "Role Policy Description",
						"LinkType": "Role",
						"Priority": 2,
						"Params": ["role-123", "role-456"]
					}
				},
				{
					"Row": {
						"PolicySet": "/Policy/InactivePolicy",
						"Description": "Inactive Policy Description",
						"LinkType": "Inactive",
						"Priority": 3
					}
				}
			]
		}
	}`

	ListPolicyLinksEmptyResponseJSON = `{
		"success": true,
		"Result": {
			"Results": []
		}
	}`

	DeletePolicyResponseJSON = `{
		"success": true
	}`

	AuthProfileResponseJSON = `{
		"success": true,
		"Result": {
			"Uuid": "auth-profile-123",
			"Name": "TestAuthProfile",
			"DurationInMinutes": 30,
			"Challenges": ["UP,SMS", ""],
			"AdditionalData": {}
		}
	}`

	AuthProfileListResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"Uuid": "auth-profile-123",
						"Name": "TestAuthProfile",
						"DurationInMinutes": 30,
						"Challenges": ["UP,SMS", ""],
						"AdditionalData": {}
					}
				}
			]
		}
	}`

	RoleResponseJSON = `{
		"success": true,
		"Result": {
			"Roles": {
				"Results": [
					{
						"Row": {
							"ID": "role-123",
							"Name": "TestRole",
							"Description": "Test Role Description",
							"AdminRights": []
						}
					}
				]
			}
		}
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

func TestCreatePolicy(t *testing.T) {
	tests := []struct {
		name               string
		createPolicy       *policymodels.IdsecIdentityCreatePolicy
		mockPostResponse   *http.Response
		mockPostError      error
		expectedPolicyName string
		expectedError      bool
		setupMock          func(service *IdsecIdentityPoliciesService)
	}{
		{
			name: "success_create_policy_without_auth_profile",
			createPolicy: &policymodels.IdsecIdentityCreatePolicy{
				PolicyName:      "TestPolicy",
				Description:     "Test Policy Description",
				AuthProfileName: "TestAuthProfile",
			},
			mockPostResponse:   MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON),
			mockPostError:      nil,
			expectedPolicyName: "TestPolicy",
			expectedError:      false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == savePolicyURL {
						return MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON), nil
					}
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksEmptyResponseJSON), nil
					}
					if path == getPolicyURL {
						return MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON), nil
					}
					return nil, errors.New("unexpected path")
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					// Check which endpoint is being called
					bodyMap, ok := body.(map[string]interface{})
					if ok {
						// If Uuid is present, it's GetProfile request
						if _, hasUuid := bodyMap["Uuid"]; hasUuid {
							return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
						}
					}
					// Otherwise it's ListAuthProfiles
					return MockHTTPResponse(http.StatusOK, AuthProfileListResponseJSON), nil
				}
			},
		},
		{
			name: "success_create_policy_with_role_names",
			createPolicy: &policymodels.IdsecIdentityCreatePolicy{
				PolicyName:      "RolePolicy",
				Description:     "Role Policy Description",
				AuthProfileName: "TestAuthProfile",
				RoleNames:       []string{"TestRole"},
			},
			mockPostResponse:   MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON),
			mockPostError:      nil,
			expectedPolicyName: "RolePolicy",
			expectedError:      false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == savePolicyURL {
						return MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON), nil
					}
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksEmptyResponseJSON), nil
					}
					if path == getPolicyURL {
						return MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON), nil
					}
					return nil, errors.New("unexpected path")
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					bodyMap, ok := body.(map[string]interface{})
					if ok {
						if _, hasUuid := bodyMap["Uuid"]; hasUuid {
							return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
						}
					}
					return MockHTTPResponse(http.StatusOK, AuthProfileListResponseJSON), nil
				}
				service.RolesService.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, RoleResponseJSON), nil
				}
				service.RolesService.DirectoriesService.DoGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil
				}
			},
		},
		{
			name: "success_create_inactive_policy",
			createPolicy: &policymodels.IdsecIdentityCreatePolicy{
				PolicyName:      "InactivePolicy",
				Description:     "Inactive Policy Description",
				AuthProfileName: "TestAuthProfile",
				PolicyStatus:    policymodels.PolicyStatusInactive,
			},
			mockPostResponse:   MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON),
			mockPostError:      nil,
			expectedPolicyName: "InactivePolicy",
			expectedError:      false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == savePolicyURL {
						return MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON), nil
					}
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksEmptyResponseJSON), nil
					}
					if path == getPolicyURL {
						return MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON), nil
					}
					return nil, errors.New("unexpected path")
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					bodyMap, ok := body.(map[string]interface{})
					if ok {
						if _, hasUuid := bodyMap["Uuid"]; hasUuid {
							return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
						}
					}
					return MockHTTPResponse(http.StatusOK, AuthProfileListResponseJSON), nil
				}
			},
		},
		{
			name: "error_missing_auth_profile_name",
			createPolicy: &policymodels.IdsecIdentityCreatePolicy{
				PolicyName:  "TestPolicy",
				Description: "Test Policy Description",
			},
			mockPostError: nil,
			expectedError: true,
		},
		{
			name: "error_http_request_failed",
			createPolicy: &policymodels.IdsecIdentityCreatePolicy{
				PolicyName:      "TestPolicy",
				AuthProfileName: "TestAuthProfile",
			},
			mockPostError: errors.New("network error"),
			expectedError: true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			createPolicy: &policymodels.IdsecIdentityCreatePolicy{
				PolicyName:      "TestPolicy",
				AuthProfileName: "TestAuthProfile",
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksEmptyResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
				}
			},
		},
		{
			name: "error_success_false",
			createPolicy: &policymodels.IdsecIdentityCreatePolicy{
				PolicyName:      "TestPolicy",
				AuthProfileName: "TestAuthProfile",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, SavePolicyFailureResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksEmptyResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, SavePolicyFailureResponseJSON), nil
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityPoliciesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityPoliciesService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.CreatePolicy(tt.createPolicy)

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

			if result.PolicyName != tt.expectedPolicyName {
				t.Errorf("Expected policy name %s, got %s", tt.expectedPolicyName, result.PolicyName)
			}
		})
	}
}

func TestUpdatePolicy(t *testing.T) {
	tests := []struct {
		name               string
		updatePolicy       *policymodels.IdsecIdentityUpdatePolicy
		mockPostResponse   *http.Response
		mockPostError      error
		expectedPolicyName string
		expectedError      bool
		setupMock          func(service *IdsecIdentityPoliciesService)
	}{
		{
			name: "success_update_policy_description",
			updatePolicy: &policymodels.IdsecIdentityUpdatePolicy{
				PolicyName:  "TestPolicy",
				Description: "Updated Description",
			},
			mockPostResponse:   MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON),
			mockPostError:      nil,
			expectedPolicyName: "TestPolicy",
			expectedError:      false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == savePolicyURL {
						return MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON), nil
					}
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
					}
					if path == getPolicyURL {
						return MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON), nil
					}
					return nil, errors.New("unexpected path")
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					bodyMap, ok := body.(map[string]interface{})
					if ok {
						if _, hasUuid := bodyMap["Uuid"]; hasUuid {
							return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
						}
					}
					return MockHTTPResponse(http.StatusOK, AuthProfileListResponseJSON), nil
				}
			},
		},
		{
			name: "success_update_policy_with_auth_profile",
			updatePolicy: &policymodels.IdsecIdentityUpdatePolicy{
				PolicyName:      "TestPolicy",
				AuthProfileName: "TestAuthProfile",
			},
			mockPostResponse:   MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON),
			mockPostError:      nil,
			expectedPolicyName: "TestPolicy",
			expectedError:      false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == savePolicyURL {
						return MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON), nil
					}
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
					}
					if path == getPolicyURL {
						return MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON), nil
					}
					return nil, errors.New("unexpected path")
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					bodyMap, ok := body.(map[string]interface{})
					if ok {
						if _, hasUuid := bodyMap["Uuid"]; hasUuid {
							return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
						}
					}
					return MockHTTPResponse(http.StatusOK, AuthProfileListResponseJSON), nil
				}
			},
		},
		{
			name: "success_update_policy_with_role_names",
			updatePolicy: &policymodels.IdsecIdentityUpdatePolicy{
				PolicyName: "TestPolicy",
				RoleNames:  []string{"TestRole"},
			},
			mockPostResponse:   MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON),
			mockPostError:      nil,
			expectedPolicyName: "TestPolicy",
			expectedError:      false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == savePolicyURL {
						return MockHTTPResponse(http.StatusOK, SavePolicyResponseJSON), nil
					}
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
					}
					if path == getPolicyURL {
						return MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON), nil
					}
					return nil, errors.New("unexpected path")
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					bodyMap, ok := body.(map[string]interface{})
					if ok {
						if _, hasUuid := bodyMap["Uuid"]; hasUuid {
							return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
						}
					}
					return MockHTTPResponse(http.StatusOK, AuthProfileListResponseJSON), nil
				}
				service.RolesService.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, RoleResponseJSON), nil
				}
				service.RolesService.DirectoriesService.DoGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			updatePolicy: &policymodels.IdsecIdentityUpdatePolicy{
				PolicyName: "TestPolicy",
			},
			mockPostError: errors.New("network error"),
			expectedError: true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			updatePolicy: &policymodels.IdsecIdentityUpdatePolicy{
				PolicyName: "TestPolicy",
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
					}
					if path == getPolicyURL {
						return MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityPoliciesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityPoliciesService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UpdatePolicy(tt.updatePolicy)

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

			if result.PolicyName != tt.expectedPolicyName {
				t.Errorf("Expected policy name %s, got %s", tt.expectedPolicyName, result.PolicyName)
			}
		})
	}
}

func TestDeletePolicy(t *testing.T) {
	tests := []struct {
		name             string
		deletePolicy     *policymodels.IdsecIdentityDeletePolicy
		mockPostResponse *http.Response
		mockPostError    error
		expectedError    bool
		setupMock        func(service *IdsecIdentityPoliciesService)
	}{
		{
			name: "success_delete_policy",
			deletePolicy: &policymodels.IdsecIdentityDeletePolicy{
				PolicyName: "TestPolicy",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, DeletePolicyResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, DeletePolicyResponseJSON), nil
				}
			},
		},
		{
			name: "success_delete_policy_with_slash_prefix",
			deletePolicy: &policymodels.IdsecIdentityDeletePolicy{
				PolicyName: "/Policy/TestPolicy",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, DeletePolicyResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, DeletePolicyResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			deletePolicy: &policymodels.IdsecIdentityDeletePolicy{
				PolicyName: "TestPolicy",
			},
			mockPostError: errors.New("network error"),
			expectedError: true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			deletePolicy: &policymodels.IdsecIdentityDeletePolicy{
				PolicyName: "TestPolicy",
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityPoliciesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityPoliciesService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			err = service.DeletePolicy(tt.deletePolicy)

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

func TestPolicy(t *testing.T) {
	tests := []struct {
		name               string
		getPolicy          *policymodels.IdsecIdentityGetPolicy
		mockPostResponse   *http.Response
		mockPostError      error
		expectedPolicyName string
		expectedError      bool
		setupMock          func(service *IdsecIdentityPoliciesService)
	}{
		{
			name: "success_get_policy",
			getPolicy: &policymodels.IdsecIdentityGetPolicy{
				PolicyName: "TestPolicy",
			},
			mockPostResponse:   MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON),
			mockPostError:      nil,
			expectedPolicyName: "TestPolicy",
			expectedError:      false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
					}
					if path == getPolicyURL {
						return MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON), nil
					}
					return nil, errors.New("unexpected path")
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					bodyMap, ok := body.(map[string]interface{})
					if ok {
						if _, hasUuid := bodyMap["Uuid"]; hasUuid {
							return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
						}
					}
					return MockHTTPResponse(http.StatusOK, AuthProfileListResponseJSON), nil
				}
			},
		},
		{
			name: "success_get_policy_with_roles",
			getPolicy: &policymodels.IdsecIdentityGetPolicy{
				PolicyName: "RolePolicy",
			},
			mockPostResponse:   MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON),
			mockPostError:      nil,
			expectedPolicyName: "RolePolicy",
			expectedError:      false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
					}
					if path == getPolicyURL {
						return MockHTTPResponse(http.StatusOK, GetPolicyResponseJSON), nil
					}
					return nil, errors.New("unexpected path")
				}
				service.RolesService.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, RoleResponseJSON), nil
				}
				service.RolesService.DirectoriesService.DoGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil
				}
				service.AuthProfileService.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					bodyMap, ok := body.(map[string]interface{})
					if ok {
						if _, hasUuid := bodyMap["Uuid"]; hasUuid {
							return MockHTTPResponse(http.StatusOK, AuthProfileResponseJSON), nil
						}
					}
					return MockHTTPResponse(http.StatusOK, AuthProfileListResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			getPolicy: &policymodels.IdsecIdentityGetPolicy{
				PolicyName: "TestPolicy",
			},
			mockPostError: errors.New("network error"),
			expectedError: true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			getPolicy: &policymodels.IdsecIdentityGetPolicy{
				PolicyName: "TestPolicy",
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == listPoliciesLinksURL {
						return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityPoliciesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityPoliciesService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.Policy(tt.getPolicy)

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

			if result.PolicyName != tt.expectedPolicyName {
				t.Errorf("Expected policy name %s, got %s", tt.expectedPolicyName, result.PolicyName)
			}
		})
	}
}

func TestListPolicies(t *testing.T) {
	tests := []struct {
		name                string
		mockPostResponse    *http.Response
		mockPostError       error
		expectedPolicyCount int
		expectedError       bool
		setupMock           func(service *IdsecIdentityPoliciesService)
	}{
		{
			name:                "success_list_policies",
			mockPostResponse:    MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON),
			mockPostError:       nil,
			expectedPolicyCount: 3,
			expectedError:       false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
				}
			},
		},
		{
			name:                "success_list_empty_policies",
			mockPostResponse:    MockHTTPResponse(http.StatusOK, ListPolicyLinksEmptyResponseJSON),
			mockPostError:       nil,
			expectedPolicyCount: 0,
			expectedError:       false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListPolicyLinksEmptyResponseJSON), nil
				}
			},
		},
		{
			name:          "error_http_request_failed",
			mockPostError: errors.New("network error"),
			expectedError: true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
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
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityPoliciesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityPoliciesService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.ListPolicies()

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

			if len(result) != tt.expectedPolicyCount {
				t.Errorf("Expected %d policies, got %d", tt.expectedPolicyCount, len(result))
			}
		})
	}
}

func TestListPoliciesBy(t *testing.T) {
	tests := []struct {
		name                string
		filters             *policymodels.IdsecIdentityPoliciesFilters
		mockPostResponse    *http.Response
		mockPostError       error
		expectedPolicyCount int
		expectedError       bool
		setupMock           func(service *IdsecIdentityPoliciesService)
	}{
		{
			name: "success_filter_by_policy_names",
			filters: &policymodels.IdsecIdentityPoliciesFilters{
				PolicyNames: []string{"TestPolicy"},
			},
			mockPostResponse:    MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON),
			mockPostError:       nil,
			expectedPolicyCount: 1,
			expectedError:       false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
				}
			},
		},
		{
			name: "success_filter_by_policy_status",
			filters: &policymodels.IdsecIdentityPoliciesFilters{
				PolicyStatus: policymodels.PolicyStatusInactive,
			},
			mockPostResponse:    MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON),
			mockPostError:       nil,
			expectedPolicyCount: 1,
			expectedError:       false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
				}
			},
		},
		{
			name: "success_filter_multiple_criteria",
			filters: &policymodels.IdsecIdentityPoliciesFilters{
				PolicyNames:  []string{"TestPolicy", "RolePolicy"},
				PolicyStatus: policymodels.PolicyStatusActive,
			},
			mockPostResponse:    MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON),
			mockPostError:       nil,
			expectedPolicyCount: 2,
			expectedError:       false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			filters: &policymodels.IdsecIdentityPoliciesFilters{
				PolicyNames: []string{"TestPolicy"},
			},
			mockPostError: errors.New("network error"),
			expectedError: true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityPoliciesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityPoliciesService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.ListPoliciesBy(tt.filters)

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

			if len(result) != tt.expectedPolicyCount {
				t.Errorf("Expected %d policies, got %d", tt.expectedPolicyCount, len(result))
			}
		})
	}
}

func TestPoliciesStats(t *testing.T) {
	tests := []struct {
		name             string
		mockPostResponse *http.Response
		mockPostError    error
		expectedStats    *policymodels.IdsecIdentityPoliciesStats
		expectedError    bool
		setupMock        func(service *IdsecIdentityPoliciesService)
	}{
		{
			name:             "success_get_policies_stats",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON),
			mockPostError:    nil,
			expectedStats: &policymodels.IdsecIdentityPoliciesStats{
				PoliciesCount: 3,
				PoliciesCountByStatus: map[string]int{
					policymodels.PolicyStatusActive:   2,
					policymodels.PolicyStatusInactive: 1,
				},
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListPolicyLinksResponseJSON), nil
				}
			},
		},
		{
			name:             "success_empty_policies_stats",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListPolicyLinksEmptyResponseJSON),
			mockPostError:    nil,
			expectedStats: &policymodels.IdsecIdentityPoliciesStats{
				PoliciesCount:         0,
				PoliciesCountByStatus: make(map[string]int),
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, ListPolicyLinksEmptyResponseJSON), nil
				}
			},
		},
		{
			name:          "error_http_request_failed",
			mockPostError: errors.New("network error"),
			expectedError: true,
			setupMock: func(service *IdsecIdentityPoliciesService) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityPoliciesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityPoliciesService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.PoliciesStats()

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

			if result.PoliciesCount != tt.expectedStats.PoliciesCount {
				t.Errorf("Expected policies count %d, got %d", tt.expectedStats.PoliciesCount, result.PoliciesCount)
			}

			if !reflect.DeepEqual(result.PoliciesCountByStatus, tt.expectedStats.PoliciesCountByStatus) {
				t.Errorf("Expected policies count by status %+v, got %+v", tt.expectedStats.PoliciesCountByStatus, result.PoliciesCountByStatus)
			}
		})
	}
}
