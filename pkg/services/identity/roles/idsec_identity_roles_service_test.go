package roles

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
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

	// Schema responses for RoleAttributes/GetAttributes
	EmptyRoleAttributesSchemaJSON = `{
		"Startindex": 1,
		"Total": 0,
		"Count": 0,
		"Attributes": []
	}`

	RoleAttributesSchemaResponseJSON = `{
		"Startindex": 1,
		"Total": 2,
		"Count": 2,
		"Attributes": [
			{
				"Name": "department",
				"ID": "attr-id-1",
				"_RowKey": "attr-id-1",
				"Type": "Text",
				"Description": "Role department"
			},
			{
				"Name": "level",
				"ID": "attr-id-2",
				"_RowKey": "attr-id-2",
				"Type": "Int",
				"Description": ""
			}
		]
	}`

	// Generic success / failure envelope
	GenericSuccessResponseJSON = `{
		"success": true,
		"Result": null,
		"Message": null
	}`

	GenericFailureResponseJSON = `{
		"success": false,
		"Result": null,
		"Message": "operation failed"
	}`

	// Empty array used as the default response for RoleAttributes/GetRoleAttributes
	EmptyRoleAttributesArrayJSON = `[]`

	// Role attribute value records as returned by RoleAttributes/GetRoleAttributes
	// in the legacy {AttributeId, ValueText} shape.
	RoleAttributesValuesLegacyJSON = `[
		{
			"ValueText": "Engineering",
			"ID": "rec-id-1",
			"_RowKey": "rec-id-1",
			"AttributeId": "attr-id-1",
			"RoleId": "role-123"
		},
		{
			"ValueText": "5",
			"ID": "rec-id-2",
			"_RowKey": "rec-id-2",
			"AttributeId": "attr-id-2",
			"RoleId": "role-123"
		}
	]`

	// Role attribute value records as returned by RoleAttributes/GetRoleAttributes
	// in the newer {Id, Name, Type, Description, Value} shape.
	RoleAttributesValuesNewJSON = `[
		{
			"Id": "attr-id-1",
			"Name": "department",
			"Type": "Text",
			"Description": "Role department",
			"Value": "Engineering"
		}
	]`
)

func TestCreate(t *testing.T) {
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
			service.DirectoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.Create(tt.createRole)

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

func TestAddAdminRights(t *testing.T) {
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
			service.DirectoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.DirectoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			_, err = service.AddAdminRights(tt.addAdminRights)

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

func TestRemoveAdminRights(t *testing.T) {
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
			service.DirectoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.DirectoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			err = service.RemoveAdminRights(tt.removeAdminRights)

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

func TestUpdate(t *testing.T) {
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
			service.DirectoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.DirectoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.Update(tt.updateRole)

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

func TestDelete(t *testing.T) {
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
			service.DirectoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.DirectoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			err = service.Delete(tt.deleteRole)

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

func TestListMembers(t *testing.T) {
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
			service.DirectoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleQueryResponseJSON), nil)
			service.DirectoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			result, err := service.ListMembers(tt.listRoleMembers)

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

func TestAddMember(t *testing.T) {
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
				service.DirectoriesService.DoTenantSuffixPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
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
			service.DirectoriesService.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleMembersResponseJSON), nil)
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DirectoriesService.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, DirectoryListResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			if tt.setupMock != nil {
				tt.setupMock(service)
			}

			result, err := service.AddMember(tt.addMember)

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

func TestRemoveMember(t *testing.T) {
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			err = service.RemoveMember(tt.removeMember)

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

func TestGetMember(t *testing.T) {
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			result, err := service.GetMember(tt.getRoleMember)

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

func TestMemberStats(t *testing.T) {
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
			service.DirectoriesService.DoTenantSuffixPost = MockPostFunc(MockHTTPResponse(http.StatusOK, TenantSuffixResponseJSON), nil)
			service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)

			result, err := service.MemberStats(tt.getRoleMembersStats)

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

// routedPostFunc returns a DoPost mock that dispatches to per-path handlers, falling
// back to a generic success response when the path does not match any handler.
func routedPostFunc(t *testing.T, handlers map[string]*http.Response) func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	t.Helper()
	return func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
		if resp, ok := handlers[path]; ok {
			return resp, nil
		}
		return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
	}
}

func TestAttributesSchema(t *testing.T) {
	tests := []struct {
		name              string
		mockPostResponse  *http.Response
		mockPostError     error
		expectedColumnIDs []string
		expectedError     bool
	}{
		{
			name:              "success_get_attribute_schema",
			mockPostResponse:  MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON),
			expectedColumnIDs: []string{"attr-id-1", "attr-id-2"},
			expectedError:     false,
		},
		{
			name:              "success_empty_schema",
			mockPostResponse:  MockHTTPResponse(http.StatusOK, EmptyRoleAttributesSchemaJSON),
			expectedColumnIDs: []string{},
			expectedError:     false,
		},
		{
			name:             "error_http_request_failed",
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name:             "error_non_200_status",
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
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

			result, err := service.AttributesSchema()

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

			if len(result.Columns) != len(tt.expectedColumnIDs) {
				t.Fatalf("Expected %d columns, got %d", len(tt.expectedColumnIDs), len(result.Columns))
			}
			for i, expectedID := range tt.expectedColumnIDs {
				if result.Columns[i].ID != expectedID {
					t.Errorf("Expected column[%d] id %s, got %s", i, expectedID, result.Columns[i].ID)
				}
			}
		})
	}
}

// schemaResponseJSON renders an attribute schema response containing the supplied columns.
// Used by the CreateAttributesSchema test cases that need fine-grained control over the
// existing-vs-refreshed schema state on each successive call.
func schemaResponseJSON(cols ...rolesmodels.IdsecIdentityRoleAttributesSchemaColumn) string {
	parts := make([]string, 0, len(cols))
	for _, col := range cols {
		parts = append(parts, fmt.Sprintf(
			`{"Name":%q,"ID":%q,"_RowKey":%q,"Type":%q,"Description":%q}`,
			col.Name, col.ID, col.ID, col.Type, col.Description,
		))
	}
	return fmt.Sprintf(`{"Startindex":1,"Total":%d,"Count":%d,"Attributes":[%s]}`, len(cols), len(cols), strings.Join(parts, ","))
}

func TestCreateAttributesSchema(t *testing.T) {
	type addCall struct {
		names []string
	}
	tests := []struct {
		name             string
		input            *rolesmodels.IdsecIdentityCreateRoleAttributesSchema
		existingSchemas  []string // ordered responses for "RoleAttributes/GetAttributes"
		expectedAddNames []string // expected names sent to AddAttributes (nil = no AddAttributes call)
		expectedUpdates  []struct {
			id   string
			desc string
		}
		expectedError bool
	}{
		{
			name: "success_create_all_new_columns_no_descriptions",
			input: &rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{Name: "department", Type: "Text"},
					{Name: "level", Type: "Int"},
				},
			},
			// Calls: 1) initial AttributesSchema (empty), 2) final AttributesSchema (both)
			existingSchemas: []string{
				schemaResponseJSON(),
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text"},
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-2", Name: "level", Type: "Int"},
				),
			},
			expectedAddNames: []string{"department", "level"},
		},
		{
			name: "success_create_with_descriptions_triggers_update",
			input: &rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{Name: "department", Type: "Text", Description: "Owning department"},
				},
			},
			// Calls: 1) initial empty schema, 2) refresh after add, 3) final return.
			existingSchemas: []string{
				schemaResponseJSON(),
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text"},
				),
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text", Description: "Owning department"},
				),
			},
			expectedAddNames: []string{"department"},
			expectedUpdates: []struct {
				id   string
				desc string
			}{{id: "attr-id-1", desc: "Owning department"}},
		},
		{
			name: "success_merge_existing_by_name_updates_description",
			input: &rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{Name: "department", Type: "Text", Description: "Updated description"},
				},
			},
			// Calls: 1) initial schema (already has 'department'), 2) final return.
			existingSchemas: []string{
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text", Description: "Original"},
				),
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text", Description: "Updated description"},
				),
			},
			expectedAddNames: nil, // No AddAttributes call expected since column already exists.
			expectedUpdates: []struct {
				id   string
				desc string
			}{{id: "attr-id-1", desc: "Updated description"}},
		},
		{
			name: "success_merge_existing_skips_when_description_unchanged",
			input: &rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{Name: "department", Type: "Text", Description: "Same"},
				},
			},
			existingSchemas: []string{
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text", Description: "Same"},
				),
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text", Description: "Same"},
				),
			},
			expectedAddNames: nil,
			expectedUpdates:  nil,
		},
		{
			name: "success_mixed_new_and_existing",
			input: &rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{Name: "department", Type: "Text", Description: "New desc"},
					{Name: "level", Type: "Int"},
				},
			},
			// Calls: 1) initial schema (has department), 2) refresh after add (has both), 3) final.
			existingSchemas: []string{
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text", Description: "Old"},
				),
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text", Description: "Old"},
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-2", Name: "level", Type: "Int"},
				),
				schemaResponseJSON(
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-1", Name: "department", Type: "Text", Description: "New desc"},
					rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{ID: "attr-id-2", Name: "level", Type: "Int"},
				),
			},
			expectedAddNames: []string{"level"},
			expectedUpdates: []struct {
				id   string
				desc string
			}{{id: "attr-id-1", desc: "New desc"}},
		},
		{
			name: "error_no_columns",
			input: &rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
				Columns: nil,
			},
			expectedError: true,
		},
		{
			name: "error_existing_schema_fetch_fails",
			input: &rolesmodels.IdsecIdentityCreateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{Name: "department", Type: "Text"},
				},
			},
			// Initial AttributesSchema returns 500
			existingSchemas: []string{},
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}

			schemaCallIdx := 0
			addCalls := []addCall{}
			updateCalls := []struct {
				id   string
				desc string
			}{}

			service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				switch path {
				case "RoleAttributes/GetAttributes":
					if schemaCallIdx >= len(tt.existingSchemas) {
						return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
					}
					payload := tt.existingSchemas[schemaCallIdx]
					schemaCallIdx++
					return MockHTTPResponse(http.StatusOK, payload), nil
				case "RoleAttributes/AddAttributes":
					bodyMap, _ := body.(map[string]interface{})
					attrs, _ := bodyMap["Attributes"].([]map[string]interface{})
					names := []string{}
					for _, a := range attrs {
						if n, ok := a["Name"].(string); ok {
							names = append(names, n)
						}
					}
					addCalls = append(addCalls, addCall{names: names})
					return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
				}
				return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
			}
			service.DoPostWithParams = func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
				p, _ := params.(map[string]string)
				bodyMap, _ := body.(map[string]interface{})
				desc, _ := bodyMap["Description"].(string)
				updateCalls = append(updateCalls, struct {
					id   string
					desc string
				}{id: p["attributeid"], desc: desc})
				return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
			}

			_, err = service.CreateAttributesSchema(tt.input)

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

			// Verify AddAttributes invocation pattern.
			if tt.expectedAddNames == nil {
				if len(addCalls) != 0 {
					t.Errorf("Expected no AddAttributes call, got %d", len(addCalls))
				}
			} else {
				if len(addCalls) != 1 {
					t.Fatalf("Expected exactly 1 AddAttributes call, got %d", len(addCalls))
				}
				if !reflect.DeepEqual(addCalls[0].names, tt.expectedAddNames) {
					t.Errorf("Expected AddAttributes names %v, got %v", tt.expectedAddNames, addCalls[0].names)
				}
			}

			// Verify UpdateAttribute invocation pattern (order-insensitive).
			if len(updateCalls) != len(tt.expectedUpdates) {
				t.Fatalf("Expected %d UpdateAttribute calls, got %d (%+v)", len(tt.expectedUpdates), len(updateCalls), updateCalls)
			}
			seen := make(map[string]string, len(updateCalls))
			for _, u := range updateCalls {
				seen[u.id] = u.desc
			}
			for _, exp := range tt.expectedUpdates {
				got, ok := seen[exp.id]
				if !ok {
					t.Errorf("Expected UpdateAttribute for id %s, not found in %+v", exp.id, updateCalls)
					continue
				}
				if got != exp.desc {
					t.Errorf("Expected UpdateAttribute for id %s with desc %q, got %q", exp.id, exp.desc, got)
				}
			}
		})
	}
}

func TestUpdateAttributesSchema(t *testing.T) {
	tests := []struct {
		name          string
		input         *rolesmodels.IdsecIdentityUpdateRoleAttributesSchema
		setupMock     func(service *IdsecIdentityRolesService, calls *map[string]int, params *[]interface{})
		expectedError bool
		assertCalls   func(t *testing.T, calls map[string]int, params []interface{})
	}{
		{
			name: "success_update_by_attribute_id",
			input: &rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{ID: "attr-id-1", Description: "new desc"},
				},
			},
			setupMock: func(service *IdsecIdentityRolesService, calls *map[string]int, params *[]interface{}) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					(*calls)[path]++
					return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
				}
				service.DoPostWithParams = func(ctx context.Context, path string, body interface{}, p interface{}) (*http.Response, error) {
					(*calls)[path]++
					*params = append(*params, p)
					return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
				}
			},
			assertCalls: func(t *testing.T, calls map[string]int, params []interface{}) {
				if calls["RoleAttributes/UpdateAttribute"] != 1 {
					t.Errorf("Expected 1 UpdateAttribute call, got %d", calls["RoleAttributes/UpdateAttribute"])
				}
				if len(params) != 1 {
					t.Fatalf("Expected 1 captured params, got %d", len(params))
				}
				p, ok := params[0].(map[string]string)
				if !ok || p["attributeid"] != "attr-id-1" {
					t.Errorf("Expected attributeid=attr-id-1 query param, got %+v", params[0])
				}
			},
		},
		{
			name: "success_update_by_name_resolved_via_schema",
			input: &rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{Name: "department", Description: "new desc"},
					{ID: "attr-id-2", Description: "another desc"},
				},
			},
			setupMock: func(service *IdsecIdentityRolesService, calls *map[string]int, params *[]interface{}) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					(*calls)[path]++
					return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
				}
				service.DoPostWithParams = func(ctx context.Context, path string, body interface{}, p interface{}) (*http.Response, error) {
					(*calls)[path]++
					*params = append(*params, p)
					return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
				}
			},
			assertCalls: func(t *testing.T, calls map[string]int, params []interface{}) {
				if calls["RoleAttributes/UpdateAttribute"] != 2 {
					t.Errorf("Expected 2 UpdateAttribute calls, got %d", calls["RoleAttributes/UpdateAttribute"])
				}
				if len(params) != 2 {
					t.Fatalf("Expected 2 captured params, got %d", len(params))
				}
				gotIDs := []string{}
				for _, p := range params {
					if pm, ok := p.(map[string]string); ok {
						gotIDs = append(gotIDs, pm["attributeid"])
					}
				}
				expected := []string{"attr-id-1", "attr-id-2"}
				if !reflect.DeepEqual(gotIDs, expected) {
					t.Errorf("Expected attribute IDs %v, got %v", expected, gotIDs)
				}
			},
		},
		{
			name: "error_no_columns",
			input: &rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
				Columns: nil,
			},
			expectedError: true,
		},
		{
			name: "error_missing_id_and_name",
			input: &rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{Description: "new desc"},
				},
			},
			expectedError: true,
		},
		{
			name: "error_unknown_name",
			input: &rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{Name: "missing", Description: "new desc"},
				},
			},
			setupMock: func(service *IdsecIdentityRolesService, calls *map[string]int, params *[]interface{}) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					(*calls)[path]++
					return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
				}
			},
			expectedError: true,
		},
		{
			name: "error_update_request_failure",
			input: &rolesmodels.IdsecIdentityUpdateRoleAttributesSchema{
				Columns: []rolesmodels.IdsecIdentityRoleAttributesSchemaColumn{
					{ID: "attr-id-1", Description: "new desc"},
				},
			},
			setupMock: func(service *IdsecIdentityRolesService, calls *map[string]int, params *[]interface{}) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					(*calls)[path]++
					return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
				}
				service.DoPostWithParams = func(ctx context.Context, path string, body interface{}, p interface{}) (*http.Response, error) {
					(*calls)[path]++
					return MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON), nil
				}
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			calls := map[string]int{}
			params := []interface{}{}
			if tt.setupMock != nil {
				tt.setupMock(service, &calls, &params)
			}

			_, err = service.UpdateAttributesSchema(tt.input)

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
			if tt.assertCalls != nil {
				tt.assertCalls(t, calls, params)
			}
		})
	}
}

func TestDeleteAttributesSchema(t *testing.T) {
	tests := []struct {
		name           string
		input          *rolesmodels.IdsecIdentityDeleteRoleAttributesSchema
		setupMock      func(service *IdsecIdentityRolesService, captured *[]string)
		expectedError  bool
		expectedDelIDs []string
	}{
		{
			name: "success_delete_by_attribute_id",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
				IDs: []string{"attr-id-1"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]string) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == "RoleAttributes/DeleteAttributes" {
						bodyMap, _ := body.(map[string]interface{})
						if ids, ok := bodyMap["AttributeIds"].([]string); ok {
							*captured = append(*captured, ids...)
						}
						return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
				}
			},
			expectedDelIDs: []string{"attr-id-1"},
		},
		{
			name: "success_delete_by_column_name_resolved",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
				IDs:         []string{"attr-id-1"},
				ColumnNames: []string{"department"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]string) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == "RoleAttributes/DeleteAttributes" {
						bodyMap, _ := body.(map[string]interface{})
						if ids, ok := bodyMap["AttributeIds"].([]string); ok {
							*captured = append(*captured, ids...)
						}
						return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
				}
			},
			expectedDelIDs: []string{"attr-id-1"},
		},
		{
			name: "success_delete_mixed_id_and_name_dedup",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
				IDs:         []string{"attr-id-1"},
				ColumnNames: []string{"department", "level"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]string) {
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					if path == "RoleAttributes/DeleteAttributes" {
						bodyMap, _ := body.(map[string]interface{})
						if ids, ok := bodyMap["AttributeIds"].([]string); ok {
							*captured = append(*captured, ids...)
						}
						return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
				}
			},
			expectedDelIDs: []string{"attr-id-1", "attr-id-2"},
		},
		{
			name: "error_no_input",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
				IDs:         nil,
				ColumnNames: nil,
			},
			expectedError: true,
		},
		{
			name: "error_unknown_name",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
				ColumnNames: []string{"missing"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]string) {
				service.DoPost = routedPostFunc(t, map[string]*http.Response{
					"RoleAttributes/GetAttributes": MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON),
				})
			},
			expectedError: true,
		},
		{
			name: "error_delete_call_failure",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributesSchema{
				IDs: []string{"attr-id-1"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]string) {
				service.DoPost = routedPostFunc(t, map[string]*http.Response{
					"RoleAttributes/DeleteAttributes": MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
				})
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			captured := []string{}
			if tt.setupMock != nil {
				tt.setupMock(service, &captured)
			}

			_, err = service.DeleteAttributesSchema(tt.input)

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
			if !reflect.DeepEqual(captured, tt.expectedDelIDs) {
				t.Errorf("Expected delete IDs %v, got %v", tt.expectedDelIDs, captured)
			}
		})
	}
}

func TestGetAttributes(t *testing.T) {
	tests := []struct {
		name               string
		input              *rolesmodels.IdsecIdentityGetRoleAttributes
		mockGetResponse    *http.Response
		mockGetError       error
		mockSchemaResponse *http.Response
		expectedError      bool
		expectedAttributes map[string]string
	}{
		{
			name: "success_legacy_shape",
			input: &rolesmodels.IdsecIdentityGetRoleAttributes{
				RoleID: "role-123",
			},
			mockGetResponse:    MockHTTPResponse(http.StatusOK, RoleAttributesValuesLegacyJSON),
			mockSchemaResponse: MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON),
			expectedAttributes: map[string]string{
				"department": "Engineering",
				"level":      "5",
			},
		},
		{
			name: "success_new_shape",
			input: &rolesmodels.IdsecIdentityGetRoleAttributes{
				RoleID: "role-123",
			},
			mockGetResponse:    MockHTTPResponse(http.StatusOK, RoleAttributesValuesNewJSON),
			mockSchemaResponse: MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON),
			expectedAttributes: map[string]string{
				"department": "Engineering",
			},
		},
		{
			name: "success_empty_records",
			input: &rolesmodels.IdsecIdentityGetRoleAttributes{
				RoleID: "role-123",
			},
			mockGetResponse:    MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON),
			mockSchemaResponse: MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON),
			expectedAttributes: map[string]string{},
		},
		{
			name: "error_missing_role_id",
			input: &rolesmodels.IdsecIdentityGetRoleAttributes{
				RoleID: "",
			},
			expectedError: true,
		},
		{
			name: "error_get_records_failure",
			input: &rolesmodels.IdsecIdentityGetRoleAttributes{
				RoleID: "role-123",
			},
			mockGetResponse: nil,
			mockGetError:    errors.New("network error"),
			expectedError:   true,
		},
		{
			name: "error_schema_fetch_failure",
			input: &rolesmodels.IdsecIdentityGetRoleAttributes{
				RoleID: "role-123",
			},
			mockGetResponse:    MockHTTPResponse(http.StatusOK, RoleAttributesValuesLegacyJSON),
			mockSchemaResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			expectedError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			service.DoGet = MockGetFunc(tt.mockGetResponse, tt.mockGetError)
			service.DoPost = MockPostFunc(tt.mockSchemaResponse, nil)

			result, err := service.GetAttributes(tt.input)

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
			if result.RoleID != tt.input.RoleID {
				t.Errorf("Expected role ID %s, got %s", tt.input.RoleID, result.RoleID)
			}
			if !reflect.DeepEqual(result.Attributes, tt.expectedAttributes) {
				t.Errorf("Expected attributes %+v, got %+v", tt.expectedAttributes, result.Attributes)
			}
		})
	}
}

func TestUpsertAttributes(t *testing.T) {
	tests := []struct {
		name          string
		input         *rolesmodels.IdsecIdentityUpsertRoleAttributes
		setupMock     func(service *IdsecIdentityRolesService, captured *[]map[string]interface{})
		expectedError bool
		expectedRole  string
		assertPayload func(t *testing.T, captured []map[string]interface{})
	}{
		{
			name: "success_upsert_known_attributes",
			input: &rolesmodels.IdsecIdentityUpsertRoleAttributes{
				RoleID: "role-123",
				Attributes: map[string]string{
					"department": "Engineering",
				},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]map[string]interface{}) {
				service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, RoleAttributesValuesNewJSON), nil)
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					switch path {
					case "RoleAttributes/GetAttributes":
						return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
					case "RoleAttributes/UpdateAttributesByRole":
						bodyMap, _ := body.(map[string]interface{})
						if attrs, ok := bodyMap["Attributes"].([]map[string]interface{}); ok {
							*captured = append(*captured, attrs...)
						}
						if roleID, ok := bodyMap["RoleId"].(string); !ok || roleID != "role-123" {
							return nil, fmt.Errorf("unexpected RoleId: %+v", bodyMap)
						}
						return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
				}
			},
			expectedRole: "role-123",
			assertPayload: func(t *testing.T, captured []map[string]interface{}) {
				if len(captured) != 1 {
					t.Fatalf("Expected 1 attribute in payload, got %d", len(captured))
				}
				attr := captured[0]
				if attr["Id"] != "attr-id-1" || attr["Name"] != "department" || attr["Type"] != "Text" || attr["Value"] != "Engineering" {
					t.Errorf("Unexpected payload attribute %+v", attr)
				}
			},
		},
		{
			name: "error_missing_role_id",
			input: &rolesmodels.IdsecIdentityUpsertRoleAttributes{
				RoleID:     "",
				Attributes: map[string]string{"department": "Engineering"},
			},
			expectedError: true,
		},
		{
			name: "error_no_attributes",
			input: &rolesmodels.IdsecIdentityUpsertRoleAttributes{
				RoleID:     "role-123",
				Attributes: map[string]string{},
			},
			expectedError: true,
		},
		{
			name: "error_unknown_attribute_in_schema",
			input: &rolesmodels.IdsecIdentityUpsertRoleAttributes{
				RoleID:     "role-123",
				Attributes: map[string]string{"missing": "value"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]map[string]interface{}) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil)
			},
			expectedError: true,
		},
		{
			name: "error_update_call_failure",
			input: &rolesmodels.IdsecIdentityUpsertRoleAttributes{
				RoleID:     "role-123",
				Attributes: map[string]string{"department": "Engineering"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]map[string]interface{}) {
				service.DoPost = routedPostFunc(t, map[string]*http.Response{
					"RoleAttributes/GetAttributes":          MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON),
					"RoleAttributes/UpdateAttributesByRole": MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
				})
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			captured := []map[string]interface{}{}
			if tt.setupMock != nil {
				tt.setupMock(service, &captured)
			}

			result, err := service.UpsertAttributes(tt.input)

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
			if result.RoleID != tt.expectedRole {
				t.Errorf("Expected role ID %s, got %s", tt.expectedRole, result.RoleID)
			}
			if tt.assertPayload != nil {
				tt.assertPayload(t, captured)
			}
		})
	}
}

func TestDeleteAttributes(t *testing.T) {
	tests := []struct {
		name          string
		input         *rolesmodels.IdsecIdentityDeleteRoleAttributes
		setupMock     func(service *IdsecIdentityRolesService, captured *[]map[string]interface{})
		expectedError bool
		assertPayload func(t *testing.T, captured []map[string]interface{})
	}{
		{
			name: "success_delete_by_attribute_names",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributes{
				RoleID:         "role-123",
				AttributeNames: []string{"department"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]map[string]interface{}) {
				service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					switch path {
					case "RoleAttributes/GetAttributes":
						return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
					case "RoleAttributes/UpdateAttributesByRole":
						bodyMap, _ := body.(map[string]interface{})
						if attrs, ok := bodyMap["Attributes"].([]map[string]interface{}); ok {
							*captured = append(*captured, attrs...)
						}
						return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
				}
			},
			assertPayload: func(t *testing.T, captured []map[string]interface{}) {
				if len(captured) != 1 {
					t.Fatalf("Expected 1 attribute in payload, got %d", len(captured))
				}
				if captured[0]["Name"] != "department" || captured[0]["Value"] != "" {
					t.Errorf("Expected blanked department attribute, got %+v", captured[0])
				}
			},
		},
		{
			name: "success_delete_by_attributes_map",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributes{
				RoleID:     "role-123",
				Attributes: map[string]string{"level": "ignored-value"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]map[string]interface{}) {
				service.DoGet = MockGetFunc(MockHTTPResponse(http.StatusOK, EmptyRoleAttributesArrayJSON), nil)
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					switch path {
					case "RoleAttributes/GetAttributes":
						return MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil
					case "RoleAttributes/UpdateAttributesByRole":
						bodyMap, _ := body.(map[string]interface{})
						if attrs, ok := bodyMap["Attributes"].([]map[string]interface{}); ok {
							*captured = append(*captured, attrs...)
						}
						return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, GenericSuccessResponseJSON), nil
				}
			},
			assertPayload: func(t *testing.T, captured []map[string]interface{}) {
				if len(captured) != 1 {
					t.Fatalf("Expected 1 attribute in payload, got %d", len(captured))
				}
				if captured[0]["Name"] != "level" || captured[0]["Value"] != "" {
					t.Errorf("Expected blanked level attribute, got %+v", captured[0])
				}
			},
		},
		{
			name: "error_missing_role_id",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributes{
				AttributeNames: []string{"department"},
			},
			expectedError: true,
		},
		{
			name: "error_no_names_or_attributes",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributes{
				RoleID: "role-123",
			},
			expectedError: true,
		},
		{
			name: "error_unknown_attribute",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributes{
				RoleID:         "role-123",
				AttributeNames: []string{"missing"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]map[string]interface{}) {
				service.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON), nil)
			},
			expectedError: true,
		},
		{
			name: "error_update_call_failure",
			input: &rolesmodels.IdsecIdentityDeleteRoleAttributes{
				RoleID:         "role-123",
				AttributeNames: []string{"department"},
			},
			setupMock: func(service *IdsecIdentityRolesService, captured *[]map[string]interface{}) {
				service.DoPost = routedPostFunc(t, map[string]*http.Response{
					"RoleAttributes/GetAttributes":          MockHTTPResponse(http.StatusOK, RoleAttributesSchemaResponseJSON),
					"RoleAttributes/UpdateAttributesByRole": MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
				})
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityRolesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityRolesService: %v", err)
			}
			captured := []map[string]interface{}{}
			if tt.setupMock != nil {
				tt.setupMock(service, &captured)
			}

			_, err = service.DeleteAttributes(tt.input)

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
			if tt.assertPayload != nil {
				tt.assertPayload(t, captured)
			}
		})
	}
}
