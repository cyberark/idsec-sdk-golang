package targetplatforms

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	targetplatformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/targetplatforms/models"
)

// NewMockResponse creates a mock HTTP response for testing.
func NewMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

// createTestService creates a properly initialized test service with mocked dependencies.
func createTestService() *IdsecPCloudTargetPlatformsService {
	service := &IdsecPCloudTargetPlatformsService{}
	service.IdsecBaseService = &services.IdsecBaseService{
		Logger: common.GetLogger("test", common.Unknown),
	}
	return service
}

// TestList tests the List method.
//
// This test validates the ability to list all target platforms.
// It tests successful listing and various error conditions.
func TestList(t *testing.T) {
	mockTargetPlatformsList := `{
		"platforms": [
			{
				"id": 1,
				"platform_id": "target-1",
				"name": "Target Platform 1",
				"system_type": "Unix",
				"active": true
			},
			{
				"id": 2,
				"platform_id": "target-2",
				"name": "Target Platform 2",
				"system_type": "Windows",
				"active": false
			}
		]
	}`

	tests := []struct {
		name             string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result []*targetplatformsmodels.IdsecPCloudTargetPlatform)
	}{
		{
			name:           "success_list_all_target_platforms",
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
			validateFunc: func(t *testing.T, result []*targetplatformsmodels.IdsecPCloudTargetPlatform) {
				if len(result) != 2 {
					t.Errorf("Expected 2 target platforms, got %d", len(result))
				}
			},
		},
		{
			name:           "success_empty_list",
			mockStatusCode: http.StatusOK,
			mockBody:       `{"platforms": []}`,
			expectedError:  false,
			validateFunc: func(t *testing.T, result []*targetplatformsmodels.IdsecPCloudTargetPlatform) {
				if len(result) != 0 {
					t.Errorf("Expected 0 target platforms, got %d", len(result))
				}
			},
		},
		{
			name:             "error_unauthorized",
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list target platforms",
		},
		{
			name:             "error_bad_request",
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "bad request"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list target platforms",
		},
		{
			name:             "error_internal_server",
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list target platforms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.List()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if tt.validateFunc != nil {
					tt.validateFunc(t, result)
				}
			}
		})
	}
}

// TestListBy tests the ListBy method.
//
// This test validates filtering target platforms by various criteria.
// It tests different filter combinations and error conditions.
func TestListBy(t *testing.T) {
	mockTargetPlatformsList := `{
		"platforms": [
			{
				"id": 1,
				"platform_id": "target-unix-1",
				"name": "Unix Target 1",
				"system_type": "Unix",
				"active": true
			},
			{
				"id": 2,
				"platform_id": "target-windows-1",
				"name": "Windows Target 1",
				"system_type": "Windows",
				"active": false
			}
		]
	}`

	tests := []struct {
		name             string
		filter           *targetplatformsmodels.IdsecPCloudTargetPlatformsFilter
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result []*targetplatformsmodels.IdsecPCloudTargetPlatform)
	}{
		{
			name: "success_filter_by_system_type",
			filter: &targetplatformsmodels.IdsecPCloudTargetPlatformsFilter{
				SystemType: "Unix",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_filter_by_active",
			filter: &targetplatformsmodels.IdsecPCloudTargetPlatformsFilter{
				Active: true,
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_filter_by_platform_id",
			filter: &targetplatformsmodels.IdsecPCloudTargetPlatformsFilter{
				PlatformID: "target-unix-*",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_filter_by_name",
			filter: &targetplatformsmodels.IdsecPCloudTargetPlatformsFilter{
				Name: "Unix*",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_multiple_filters",
			filter: &targetplatformsmodels.IdsecPCloudTargetPlatformsFilter{
				Active:         true,
				SystemType:     "Unix",
				PeriodicVerify: true,
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name:             "error_unauthorized",
			filter:           &targetplatformsmodels.IdsecPCloudTargetPlatformsFilter{},
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list target platforms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.ListBy(tt.filter)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if tt.validateFunc != nil {
					tt.validateFunc(t, result)
				}
			}
		})
	}
}

// TestGet tests the Get method.
//
// This test validates retrieval of a specific target platform by ID.
// It tests successful retrieval and various error conditions.
func TestGet(t *testing.T) {
	mockTargetPlatformsList := `{
		"platforms": [
			{
				"id": 123,
				"platform_id": "target-123",
				"name": "Test Target Platform"
			},
			{
				"id": 456,
				"platform_id": "target-456",
				"name": "Another Platform"
			}
		]
	}`

	tests := []struct {
		name             string
		targetPlatformID int
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:             "success_get_target_platform",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusOK,
			mockBody:         mockTargetPlatformsList,
			expectedError:    false,
		},
		{
			name:             "error_not_found",
			targetPlatformID: 999,
			mockStatusCode:   http.StatusOK,
			mockBody:         mockTargetPlatformsList,
			expectedError:    true,
			expectedErrorMsg: "failed to get target platform",
		},
		{
			name:             "error_unauthorized",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list target platforms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.Get(&targetplatformsmodels.IdsecPCloudGetTargetPlatform{
				TargetPlatformID: tt.targetPlatformID,
			})

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if result.ID != tt.targetPlatformID {
					t.Errorf("Expected target platform ID %d, got %d", tt.targetPlatformID, result.ID)
				}
			}
		})
	}
}

// TestActivate tests the Activate method.
//
// This test validates activating a target platform by ID.
// It tests successful activation and various error conditions.
func TestActivate(t *testing.T) {
	tests := []struct {
		name             string
		targetPlatformID int
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:             "success_activate_target_platform",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusOK,
			mockBody:         `{}`,
			expectedError:    false,
		},
		{
			name:             "error_not_found",
			targetPlatformID: 999,
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "target platform not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to activate target platform",
		},
		{
			name:             "error_unauthorized",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to activate target platform",
		},
		{
			name:             "error_bad_request",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "platform already active"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to activate target platform",
		},
		{
			name:             "error_internal_server",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to activate target platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			err := service.Activate(&targetplatformsmodels.IdsecPCloudActivateTargetPlatform{
				TargetPlatformID: tt.targetPlatformID,
			})

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestDeactivate tests the Deactivate method.
//
// This test validates deactivating a target platform by ID.
// It tests successful deactivation and various error conditions.
func TestDeactivate(t *testing.T) {
	tests := []struct {
		name             string
		targetPlatformID int
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:             "success_deactivate_target_platform",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusOK,
			mockBody:         `{}`,
			expectedError:    false,
		},
		{
			name:             "error_not_found",
			targetPlatformID: 999,
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "target platform not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to deactivate target platform",
		},
		{
			name:             "error_unauthorized",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to deactivate target platform",
		},
		{
			name:             "error_bad_request",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "platform already inactive"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to deactivate target platform",
		},
		{
			name:             "error_internal_server",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to deactivate target platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			err := service.Deactivate(&targetplatformsmodels.IdsecPCloudDeactivateTargetPlatform{
				TargetPlatformID: tt.targetPlatformID,
			})

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestDuplicate tests the Duplicate method.
//
// This test validates duplicating a target platform by ID.
// It tests successful duplication and various error conditions.
func TestDuplicate(t *testing.T) {
	tests := []struct {
		name             string
		targetPlatformID int
		newName          string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:             "success_duplicate_target_platform",
			targetPlatformID: 123,
			newName:          "Duplicated Platform",
			mockStatusCode:   http.StatusOK,
			mockBody:         `{"id": 456, "platform_id": "duplicated-platform"}`,
			expectedError:    false,
		},
		{
			name:             "error_not_found",
			targetPlatformID: 999,
			newName:          "Duplicated Platform",
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "target platform not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to duplicate target platform",
		},
		{
			name:             "error_unauthorized",
			targetPlatformID: 123,
			newName:          "Duplicated Platform",
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to duplicate target platform",
		},
		{
			name:             "error_conflict",
			targetPlatformID: 123,
			newName:          "Existing Name",
			mockStatusCode:   http.StatusConflict,
			mockBody:         `{"error": "platform name already exists"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to duplicate target platform",
		},
		{
			name:             "error_bad_request",
			targetPlatformID: 123,
			newName:          "",
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "invalid name"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to duplicate target platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.Duplicate(&targetplatformsmodels.IdsecPCloudDuplicateTargetPlatform{
				TargetPlatformID: tt.targetPlatformID,
				Name:             tt.newName,
			})

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if result == nil {
					t.Errorf("Expected result, got nil")
				}
			}
		})
	}
}

// TestDelete tests the Delete method.
//
// This test validates deleting a target platform by ID.
// It tests successful deletion and various error conditions.
func TestDelete(t *testing.T) {
	tests := []struct {
		name             string
		targetPlatformID int
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:             "success_delete_target_platform",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusNoContent,
			mockBody:         "",
			expectedError:    false,
		},
		{
			name:             "error_not_found",
			targetPlatformID: 999,
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "target platform not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete target platform",
		},
		{
			name:             "error_unauthorized",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete target platform",
		},
		{
			name:             "error_forbidden",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusForbidden,
			mockBody:         `{"error": "forbidden"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete target platform",
		},
		{
			name:             "error_conflict_in_use",
			targetPlatformID: 123,
			mockStatusCode:   http.StatusConflict,
			mockBody:         `{"error": "platform is in use"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete target platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doDelete = func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			err := service.Delete(&targetplatformsmodels.IdsecPCloudDeleteTargetPlatform{
				TargetPlatformID: tt.targetPlatformID,
			})

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestStats tests the Stats method.
//
// This test validates target platform statistics calculation.
// It tests successful stats generation and error conditions.
func TestStats(t *testing.T) {
	tests := []struct {
		name             string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *targetplatformsmodels.IdsecPCloudTargetPlatformsStats)
	}{
		{
			name:           "success_calculate_stats",
			mockStatusCode: http.StatusOK,
			mockBody: `{
				"platforms": [
					{"system_type": "Unix", "active": true},
					{"system_type": "Windows", "active": false},
					{"system_type": "Unix", "active": true}
				]
			}`,
			expectedError: false,
			validateFunc: func(t *testing.T, result *targetplatformsmodels.IdsecPCloudTargetPlatformsStats) {
				if result.TargetPlatformsCount != 3 {
					t.Errorf("Expected 3 target platforms, got %d", result.TargetPlatformsCount)
				}
				if result.ActiveTargetPlatformsCount != 2 {
					t.Errorf("Expected 2 active platforms, got %d", result.ActiveTargetPlatformsCount)
				}
				if result.TargetPlatformsCountBySystemType["Unix"] != 2 {
					t.Errorf("Expected 2 Unix platforms, got %d", result.TargetPlatformsCountBySystemType["Unix"])
				}
			},
		},
		{
			name:           "success_empty_platforms",
			mockStatusCode: http.StatusOK,
			mockBody:       `{"platforms": []}`,
			expectedError:  false,
			validateFunc: func(t *testing.T, result *targetplatformsmodels.IdsecPCloudTargetPlatformsStats) {
				if result.TargetPlatformsCount != 0 {
					t.Errorf("Expected 0 target platforms, got %d", result.TargetPlatformsCount)
				}
			},
		},
		{
			name:             "error_unauthorized",
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list target platforms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.Stats()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if tt.validateFunc != nil {
					tt.validateFunc(t, result)
				}
			}
		})
	}
}

// TestImport tests the Import method.
//
// This test validates importing a target platform from a zip file.
// It tests successful import and various error conditions.
func TestImport(t *testing.T) {
	mockTargetPlatformsList := `{
		"platforms": [
			{
				"id": 123,
				"platform_id": "imported-platform",
				"name": "Imported Platform"
			}
		]
	}`

	tests := []struct {
		name             string
		setupFile        func(t *testing.T) string
		mockStatusCode   int
		mockBody         string
		mockGetBody      string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "success_import_target_platform",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "target-platform.zip")
				err := os.WriteFile(tmpFile, []byte("fake zip content"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockStatusCode: http.StatusCreated,
			mockBody:       `{"platform_id": "imported-platform"}`,
			mockGetBody:    mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name: "error_file_not_found",
			setupFile: func(t *testing.T) string {
				return "/nonexistent/target-platform.zip"
			},
			expectedError:    true,
			expectedErrorMsg: "given path",
		},
		{
			name: "error_bad_request",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "target-platform.zip")
				err := os.WriteFile(tmpFile, []byte("invalid content"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "invalid zip file"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to import target platform",
		},
		{
			name: "error_unauthorized",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "target-platform.zip")
				err := os.WriteFile(tmpFile, []byte("fake zip content"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to import target platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(http.StatusOK, tt.mockGetBody), nil
			}

			filePath := tt.setupFile(t)
			_, err := service.Import(&targetplatformsmodels.IdsecPCloudImportTargetPlatform{
				PlatformZipPath: filePath,
			})

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestExport tests the Export method.
//
// This test validates exporting a target platform to a zip file.
// It tests successful export and various error conditions.
func TestExport(t *testing.T) {
	tests := []struct {
		name             string
		targetPlatformID int
		setupFolder      func(t *testing.T) string
		mockStatusCode   int
		mockBody         string
		mockGetBody      string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:             "success_export_target_platform",
			targetPlatformID: 123,
			setupFolder: func(t *testing.T) string {
				return t.TempDir()
			},
			mockStatusCode: http.StatusOK,
			mockBody:       "fake zip content",
			mockGetBody: `{
				"platforms": [{"id": 123, "platform_id": "target-123"}]
			}`,
			expectedError: false,
		},
		{
			name:             "error_platform_not_found",
			targetPlatformID: 999,
			setupFolder: func(t *testing.T) string {
				return t.TempDir()
			},
			mockStatusCode:   http.StatusOK,
			mockBody:         "",
			mockGetBody:      `{"platforms": []}`,
			expectedError:    true,
			expectedErrorMsg: "failed to get target platform",
		},
		{
			name:             "error_unauthorized_on_export",
			targetPlatformID: 123,
			setupFolder: func(t *testing.T) string {
				return t.TempDir()
			},
			mockStatusCode: http.StatusUnauthorized,
			mockBody:       `{"error": "unauthorized"}`,
			mockGetBody: `{
				"platforms": [{"id": 123, "platform_id": "target-123"}]
			}`,
			expectedError:    true,
			expectedErrorMsg: "failed to export target platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(http.StatusOK, tt.mockGetBody), nil
			}

			outputFolder := tt.setupFolder(t)
			err := service.Export(&targetplatformsmodels.IdsecPCloudExportTargetPlatform{
				TargetPlatformID: tt.targetPlatformID,
				OutputFolder:     outputFolder,
			})

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}
