package roles

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
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
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
	CreateRoleResponseJSON = `{
		"success": true,
		"Result": {
			"_RowKey": "role-123"
		}
	}`

	CreateRoleFailureResponseJSON = `{
		"success": false
	}`

	RoleMembersResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"Guid": "user-123",
						"Name": "john.doe",
						"Type": "user"
					}
				},
				{
					"Row": {
						"Guid": "group-456",
						"Name": "developers",
						"Type": "group"
					}
				}
			]
		}
	}`

	RoleMembersEmptyResponseJSON = `{
		"success": true,
		"Result": {
			"Results": []
		}
	}`

	RoleMembersWithJohnDoeResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"Guid": "user-john-123",
						"Name": "john.doe",
						"Type": "user"
					}
				}
			]
		}
	}`

	RoleMembersWithDevelopersResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"Guid": "group-dev-456",
						"Name": "developers",
						"Type": "group"
					}
				}
			]
		}
	}`

	ListRolesResponseJSON = `{
		"success": true,
		"Result": {
			"Roles": {
				"Results": [
					{
						"Row": {
							"ID": "role-1",
							"Name": "Admin",
							"Description": "Administrator role",
							"AdminRights": []
						}
					},
					{
						"Row": {
							"ID": "role-2",
							"Name": "User",
							"Description": "User role",
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

	RoleQueryResponseJSON = `{
		"success": true,
		"Result": {
			"Roles": {
				"Results": [
					{
						"Row": {
							"ID": "role-123",
							"Name": "AdminRole",
							"Description": "Test Role Description",
							"AdminRights": [
								{
									"Path": "/admin/path1"
								}
							]
						}
					}
				]
			}
		}
	}`

	AddAdminRightsResponseJSON = `{
		"success": true
	}`

	RemoveAdminRightsResponseJSON = `{
		"success": true
	}`

	DeleteRoleResponseJSON = `{
		"success": true
	}`

	AddMemberResponseJSON = `{
		"success": true
	}`

	RemoveMemberResponseJSON = `{
		"success": true
	}`

	UpdateRoleResponseJSON = `{
		"success": true
	}`

	ErrorResponseJSON = `{
		"success": false,
		"error": "operation failed"
	}`

	EmptyResultResponseJSON = `{
		"success": true,
		"Result": {
			"Roles": {
				"Results": []
			}
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
)

func TestCreateRole(t *testing.T) {
	tests := []struct {
		name                              string
		createRole                        *rolesmodels.IdsecIdentityCreateRole
		mockPostResponse                  *http.Response
		mockAdminRightsPostResponse       *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockGetResponse                   *http.Response
		mockPostError                     error
		expectedRole                      *rolesmodels.IdsecIdentityRole
		expectedError                     bool
		setupMock                         func(service *IdsecIdentityRolesService)
	}{
		{
			name: "success_create_role_without_admin_rights",
			createRole: &rolesmodels.IdsecIdentityCreateRole{
				RoleName:    "AdminRole",
				Description: "Test Role Description",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, CreateRoleResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, EmptyResultResponseJSON),
			mockGetResponse:                   MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON),
			mockPostError:                     nil,
			expectedRole: &rolesmodels.IdsecIdentityRole{
				RoleID:   "role-123",
				RoleName: "AdminRole",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityRolesService) {
				callCount := 0
				service.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						// Role lookup - return not found
						return MockHTTPResponse(http.StatusOK, EmptyResultResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					// Role creation
					return MockHTTPResponse(http.StatusOK, CreateRoleResponseJSON), nil
				}
			},
		},
		{
			name: "success_create_role_with_admin_rights",
			createRole: &rolesmodels.IdsecIdentityCreateRole{
				RoleName:    "AdminRole",
				Description: "Admin Role Description",
				AdminRights: []string{"/admin/path1", "/admin/path2"},
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, CreateRoleResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, EmptyResultResponseJSON),
			mockGetResponse:                   MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON),
			mockPostError:                     nil,
			expectedRole: &rolesmodels.IdsecIdentityRole{
				RoleID:      "role-123",
				RoleName:    "AdminRole",
				AdminRights: []string{"/admin/path1", "/admin/path2"},
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityRolesService) {
				queryCallCount := 0
				postCallCount := 0
				service.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					queryCallCount++
					if queryCallCount == 1 {
						// Role lookup - return not found
						return MockHTTPResponse(http.StatusOK, EmptyResultResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					postCallCount++
					// Role creation and admin rights addition
					return MockHTTPResponse(http.StatusOK, CreateRoleResponseJSON), nil
				}
				service.DoAdminRightsPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			createRole: &rolesmodels.IdsecIdentityCreateRole{
				RoleName: "AdminRole",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
			setupMock: func(service *IdsecIdentityRolesService) {
				service.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return nil, errors.New("network error")
				}
			},
		},
		{
			name: "error_non_200_status",
			createRole: &rolesmodels.IdsecIdentityCreateRole{
				RoleName: "AdminRole",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, EmptyResultResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockPostError:                     nil,
			expectedError:                     true,
			setupMock: func(service *IdsecIdentityRolesService) {
				service.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, EmptyResultResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
		},
		{
			name: "error_success_false",
			createRole: &rolesmodels.IdsecIdentityCreateRole{
				RoleName: "AdminRole",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, CreateRoleFailureResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, EmptyResultResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockPostError:                     nil,
			expectedError:                     true,
			setupMock: func(service *IdsecIdentityRolesService) {
				service.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, EmptyResultResponseJSON), nil
				}
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, CreateRoleFailureResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.directoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.CreateRole(tt.createRole)

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

			if result.RoleID != tt.expectedRole.RoleID {
				t.Errorf("Expected role ID %s, got %s", tt.expectedRole.RoleID, result.RoleID)
			}
			if result.RoleName != tt.expectedRole.RoleName {
				t.Errorf("Expected role name %s, got %s", tt.expectedRole.RoleName, result.RoleName)
			}
		})
	}
}

func TestAddAdminRightsToRole(t *testing.T) {
	tests := []struct {
		name                              string
		addAdminRights                    *rolesmodels.IdsecIdentityAddAdminRightsToRole
		mockPostResponse                  *http.Response
		mockAdminRightsPostResponse       *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockPostError                     error
		expectedError                     bool
		setupMock                         func(service *IdsecIdentityRolesService)
	}{
		{
			name: "success_add_admin_rights_with_role_id",
			addAdminRights: &rolesmodels.IdsecIdentityAddAdminRightsToRole{
				RoleID:      "role-123",
				AdminRights: []string{"/admin/path1", "/admin/path2"},
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, ListRolesResponseJSON),
			mockPostError:                     nil,
			expectedError:                     false,
		},
		{
			name: "success_add_admin_rights_with_role_name",
			addAdminRights: &rolesmodels.IdsecIdentityAddAdminRightsToRole{
				RoleName:    "AdminRole",
				AdminRights: []string{"/admin/path1"},
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedError:                     false,
			setupMock: func(service *IdsecIdentityRolesService) {
				service.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil
				}
			},
		},
		{
			name: "error_no_role_id_or_name",
			addAdminRights: &rolesmodels.IdsecIdentityAddAdminRightsToRole{
				AdminRights: []string{"/admin/path1"},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_http_request_failed",
			addAdminRights: &rolesmodels.IdsecIdentityAddAdminRightsToRole{
				RoleID:      "role-123",
				AdminRights: []string{"/admin/path1"},
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name: "error_non_200_status",
			addAdminRights: &rolesmodels.IdsecIdentityAddAdminRightsToRole{
				RoleID:      "role-123",
				AdminRights: []string{"/admin/path1"},
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusBadRequest, ErrorResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusBadRequest, ErrorResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, ListRolesResponseJSON),
			mockPostError:                     nil,
			expectedError:                     true,
			setupMock: func(service *IdsecIdentityRolesService) {
				service.DoAdminRightsPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusBadRequest, ErrorResponseJSON), nil
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoAdminRightsPost = MockPostFunc(tt.mockAdminRightsPostResponse, tt.mockPostError)
			service.DoDirectoryServiceQueryPost = MockPostFunc(tt.mockDirectoryServiceQueryResponse, tt.mockPostError)
			service.directoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.directoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			err = service.AddAdminRightsToRole(tt.addAdminRights)

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

func TestRemoveAdminRightsFromRole(t *testing.T) {
	tests := []struct {
		name                              string
		removeAdminRights                 *rolesmodels.IdsecIdentityRemoveAdminRightsToRole
		mockPostResponse                  *http.Response
		mockAdminRightsPostResponse       *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockPostError                     error
		expectedError                     bool
		setupMock                         func(service *IdsecIdentityRolesService)
	}{
		{
			name: "success_remove_admin_rights_with_role_id",
			removeAdminRights: &rolesmodels.IdsecIdentityRemoveAdminRightsToRole{
				RoleID:      "role-123",
				AdminRights: []string{"/admin/path1"},
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RemoveAdminRightsResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, RemoveAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, ListRolesResponseJSON),
			expectedError:                     false,
		},
		{
			name: "success_remove_admin_rights_with_role_name",
			removeAdminRights: &rolesmodels.IdsecIdentityRemoveAdminRightsToRole{
				RoleName:    "AdminRole",
				AdminRights: []string{"/admin/path1"},
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RemoveAdminRightsResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, RemoveAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedError:                     false,
			setupMock: func(service *IdsecIdentityRolesService) {
				service.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil
				}
			},
		},
		{
			name: "error_no_role_id_or_name",
			removeAdminRights: &rolesmodels.IdsecIdentityRemoveAdminRightsToRole{
				AdminRights: []string{"/admin/path1"},
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoAdminRightsPost = MockPostFunc(tt.mockAdminRightsPostResponse, tt.mockPostError)
			service.DoDirectoryServiceQueryPost = MockPostFunc(tt.mockDirectoryServiceQueryResponse, tt.mockPostError)
			service.directoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.directoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			err = service.RemoveAdminRightsFromRole(tt.removeAdminRights)

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

func TestUpdateRole(t *testing.T) {
	tests := []struct {
		name                              string
		updateRole                        *rolesmodels.IdsecIdentityUpdateRole
		mockAdminRightsPostResponse       *http.Response
		mockPostResponse                  *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockPostError                     error
		expectedRole                      *rolesmodels.IdsecIdentityRole
		expectedError                     bool
		setupMock                         func(service *IdsecIdentityRolesService)
	}{
		{
			name: "success_update_role_with_id",
			updateRole: &rolesmodels.IdsecIdentityUpdateRole{
				RoleID:      "role-123",
				RoleName:    "UpdatedRole",
				Description: "Updated Description",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, UpdateRoleResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedRole: &rolesmodels.IdsecIdentityRole{
				RoleID:   "role-123",
				RoleName: "AdminRole",
			},
			expectedError: false,
			setupMock: func(service *IdsecIdentityRolesService) {
				service.DoDirectoryServiceQueryPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			updateRole: &rolesmodels.IdsecIdentityUpdateRole{
				RoleID: "role-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
			service.DoAdminRightsPost = MockPostFunc(tt.mockAdminRightsPostResponse, tt.mockPostError)
			service.DoDirectoryServiceQueryPost = MockPostFunc(tt.mockDirectoryServiceQueryResponse, tt.mockPostError)
			service.directoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.directoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.UpdateRole(tt.updateRole)

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
				t.Errorf("Expected role result, got nil")
			}
		})
	}
}

func TestDeleteRole(t *testing.T) {
	tests := []struct {
		name                              string
		deleteRole                        *rolesmodels.IdsecIdentityDeleteRole
		mockAdminRightsPostResponse       *http.Response
		mockPostResponse                  *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockPostError                     error
		expectedError                     bool
	}{
		{
			name: "success_delete_role_with_id",
			deleteRole: &rolesmodels.IdsecIdentityDeleteRole{
				RoleID: "role-123",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, DeleteRoleResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, ListRolesResponseJSON),
			mockPostError:                     nil,
			expectedError:                     false,
		},
		{
			name: "success_delete_role_with_name",
			deleteRole: &rolesmodels.IdsecIdentityDeleteRole{
				RoleName: "AdminRole",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, DeleteRoleResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, ListRolesResponseJSON),
			mockPostError:                     nil,
			expectedError:                     false,
		},
		{
			name: "error_http_request_failed",
			deleteRole: &rolesmodels.IdsecIdentityDeleteRole{
				RoleID: "role-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name: "error_non_200_status",
			deleteRole: &rolesmodels.IdsecIdentityDeleteRole{
				RoleID: "role-123",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockAdminRightsPostResponse:       MockHTTPResponse(http.StatusOK, AddAdminRightsResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, ListRolesResponseJSON),
			mockPostError:                     nil,
			expectedError:                     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
			service.DoAdminRightsPost = MockPostFunc(tt.mockAdminRightsPostResponse, tt.mockPostError)
			service.DoDirectoryServiceQueryPost = MockPostFunc(tt.mockDirectoryServiceQueryResponse, tt.mockPostError)
			service.directoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.directoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			err = service.DeleteRole(tt.deleteRole)

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

func TestListRoleMembers(t *testing.T) {
	tests := []struct {
		name                              string
		listRoleMembers                   *rolesmodels.IdsecIdentityListRoleMembers
		mockPostResponse                  *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockPostError                     error
		expectedMembersLen                int
		expectedError                     bool
	}{
		{
			name: "success_list_role_members",
			listRoleMembers: &rolesmodels.IdsecIdentityListRoleMembers{
				RoleID: "role-123",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RoleMembersResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedMembersLen:                2,
			expectedError:                     false,
		},
		{
			name: "success_list_empty_role_members",
			listRoleMembers: &rolesmodels.IdsecIdentityListRoleMembers{
				RoleID: "role-456",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RoleMembersEmptyResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedMembersLen:                0,
			expectedError:                     false,
		},
		{
			name: "error_http_request_failed",
			listRoleMembers: &rolesmodels.IdsecIdentityListRoleMembers{
				RoleID: "role-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name: "error_non_200_status",
			listRoleMembers: &rolesmodels.IdsecIdentityListRoleMembers{
				RoleID: "role-123",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedError:                     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
			service.DoDirectoryServiceQueryPost = MockPostFunc(tt.mockDirectoryServiceQueryResponse, tt.mockPostError)
			service.directoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.directoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			result, err := service.ListRoleMembers(tt.listRoleMembers)

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

			if len(result) != tt.expectedMembersLen {
				t.Errorf("Expected %d members, got %d", tt.expectedMembersLen, len(result))
			}
		})
	}
}

func TestAddMemberToRole(t *testing.T) {
	tests := []struct {
		name                              string
		addMember                         *rolesmodels.IdsecIdentityAddMemberToRole
		mockPostResponse                  *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockPostError                     error
		expectedError                     bool
		setupMock                         func(service *IdsecIdentityRolesService)
	}{
		{
			name: "success_add_group_to_role",
			addMember: &rolesmodels.IdsecIdentityAddMemberToRole{
				RoleID:     "role-123",
				MemberName: "developers",
				MemberType: directoriesmodels.EntityTypeGroup,
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, AddMemberResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedError:                     false,
			setupMock: func(service *IdsecIdentityRolesService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						// AddMemberToRole post call
						return MockHTTPResponse(http.StatusOK, AddMemberResponseJSON), nil
					}
					// ListRoleMembers call after adding - return the member that was just added
					return MockHTTPResponse(http.StatusOK, RoleMembersWithDevelopersResponseJSON), nil
				}
				service.directoriesService.DoTenantSuffixPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					return MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil
				}
			},
		},
		{
			name: "error_http_request_failed",
			addMember: &rolesmodels.IdsecIdentityAddMemberToRole{
				RoleID:     "role-123",
				MemberName: "john.doe",
				MemberType: directoriesmodels.EntityTypeUser,
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
			service.DoDirectoryServiceQueryPost = MockPostFunc(tt.mockDirectoryServiceQueryResponse, tt.mockPostError)
			service.directoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleMembersResponseJSON), nil)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.directoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.AddMemberToRole(tt.addMember)

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
				t.Errorf("Expected member result, got nil")
			}
		})
	}
}

func TestRemoveMemberFromRole(t *testing.T) {
	tests := []struct {
		name                              string
		removeMember                      *rolesmodels.IdsecIdentityRemoveMemberFromRole
		mockPostResponse                  *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockPostError                     error
		expectedError                     bool
	}{
		{
			name: "success_remove_user_from_role",
			removeMember: &rolesmodels.IdsecIdentityRemoveMemberFromRole{
				RoleID:     "role-123",
				MemberName: "john.doe",
				MemberType: directoriesmodels.EntityTypeUser,
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RemoveMemberResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedError:                     false,
		},
		{
			name: "success_remove_group_from_role",
			removeMember: &rolesmodels.IdsecIdentityRemoveMemberFromRole{
				RoleID:     "role-123",
				MemberName: "developers",
				MemberType: directoriesmodels.EntityTypeGroup,
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RemoveMemberResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedError:                     false,
		},
		{
			name: "error_http_request_failed",
			removeMember: &rolesmodels.IdsecIdentityRemoveMemberFromRole{
				RoleID:     "role-123",
				MemberName: "john.doe",
				MemberType: directoriesmodels.EntityTypeUser,
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
			service.DoDirectoryServiceQueryPost = MockPostFunc(tt.mockDirectoryServiceQueryResponse, tt.mockPostError)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			err = service.RemoveMemberFromRole(tt.removeMember)

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

func TestRoleMember(t *testing.T) {
	tests := []struct {
		name                              string
		getRoleMember                     *rolesmodels.IdsecIdentityGetRoleMember
		mockPostResponse                  *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockPostError                     error
		expectedMember                    *rolesmodels.IdsecIdentityRoleMember
		expectedError                     bool
	}{
		{
			name: "success_get_member_by_id",
			getRoleMember: &rolesmodels.IdsecIdentityGetRoleMember{
				RoleID:   "role-123",
				MemberID: "user-123",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RoleMembersResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedMember: &rolesmodels.IdsecIdentityRoleMember{
				RoleID:     "role-123",
				MemberID:   "user-123",
				MemberName: "john.doe",
				MemberType: "USER",
			},
			expectedError: false,
		},
		{
			name: "success_get_member_by_name",
			getRoleMember: &rolesmodels.IdsecIdentityGetRoleMember{
				RoleID:     "role-123",
				MemberName: "john.doe",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RoleMembersResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedMember: &rolesmodels.IdsecIdentityRoleMember{
				RoleID:     "role-123",
				MemberID:   "user-123",
				MemberName: "john.doe",
				MemberType: "USER",
			},
			expectedError: false,
		},
		{
			name: "error_no_role_id",
			getRoleMember: &rolesmodels.IdsecIdentityGetRoleMember{
				MemberID: "user-123",
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_member_not_found",
			getRoleMember: &rolesmodels.IdsecIdentityGetRoleMember{
				RoleID:   "role-123",
				MemberID: "nonexistent-123",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RoleMembersResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedError:                     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
			service.DoDirectoryServiceQueryPost = MockPostFunc(tt.mockDirectoryServiceQueryResponse, tt.mockPostError)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			result, err := service.RoleMember(tt.getRoleMember)

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

			if !reflect.DeepEqual(result, tt.expectedMember) {
				t.Errorf("Expected member %+v, got %+v", tt.expectedMember, result)
			}
		})
	}
}

func TestRoleMembersStats(t *testing.T) {
	tests := []struct {
		name                              string
		getRoleMembersStats               *rolesmodels.IdsecIdentityGetRoleMembersStats
		mockPostResponse                  *http.Response
		mockDirectoryServiceQueryResponse *http.Response
		mockPostError                     error
		expectedStats                     *rolesmodels.IdsecIdentityRoleMembersStats
		expectedError                     bool
	}{
		{
			name: "success_get_members_stats",
			getRoleMembersStats: &rolesmodels.IdsecIdentityGetRoleMembersStats{
				RoleID: "role-123",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RoleMembersResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedStats: &rolesmodels.IdsecIdentityRoleMembersStats{
				MembersCount: 2,
				MembersCountByType: map[string]int{
					"USER":  1,
					"GROUP": 1,
				},
			},
			expectedError: false,
		},
		{
			name: "success_empty_members_stats",
			getRoleMembersStats: &rolesmodels.IdsecIdentityGetRoleMembersStats{
				RoleID: "role-456",
			},
			mockPostResponse:                  MockHTTPResponse(http.StatusOK, RoleMembersEmptyResponseJSON),
			mockDirectoryServiceQueryResponse: MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON),
			mockPostError:                     nil,
			expectedStats: &rolesmodels.IdsecIdentityRoleMembersStats{
				MembersCount:       0,
				MembersCountByType: make(map[string]int),
			},
			expectedError: false,
		},
		{
			name: "error_http_request_failed",
			getRoleMembersStats: &rolesmodels.IdsecIdentityGetRoleMembersStats{
				RoleID: "role-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
			service.DoDirectoryServiceQueryPost = MockPostFunc(tt.mockDirectoryServiceQueryResponse, tt.mockPostError)
			service.directoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)

			result, err := service.RoleMembersStats(tt.getRoleMembersStats)

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

			if result.MembersCount != tt.expectedStats.MembersCount {
				t.Errorf("Expected members count %d, got %d", tt.expectedStats.MembersCount, result.MembersCount)
			}

			if !reflect.DeepEqual(result.MembersCountByType, tt.expectedStats.MembersCountByType) {
				t.Errorf("Expected members count by type %+v, got %+v", tt.expectedStats.MembersCountByType, result.MembersCountByType)
			}
		})
	}
}
