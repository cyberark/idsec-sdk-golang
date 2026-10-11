package targetplatforms

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
				ID: &tt.targetPlatformID,
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
				ID: &tt.targetPlatformID,
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
				ID: &tt.targetPlatformID,
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
				ID:   &tt.targetPlatformID,
				Name: tt.newName,
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
				ID: &tt.targetPlatformID,
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
			mockGetBody:      `{"platforms": []}`,
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
			mockGetBody:      `{"platforms": []}`,
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
			mockGetBody:      `{"platforms": []}`,
			expectedError:    true,
			expectedErrorMsg: "failed to import target platform",
		},
		{
			name: "error_platform_limit_reached",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "target-platform.zip")
				if err := os.WriteFile(tmpFile, []byte("fake zip content"), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockGetBody: func() string {
				platforms := make([]string, maxTargetPlatforms)
				for i := range platforms {
					platforms[i] = `{"id": 1, "platform_id": "p", "name": "p"}`
				}
				return `{"platforms": [` + strings.Join(platforms, ",") + `]}`
			}(),
			expectedError:    true,
			expectedErrorMsg: "cannot import platform",
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
				ID:           &tt.targetPlatformID,
				OutputFolder: outputFolder,
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

// mockTargetPlatformsBody returns a target platforms list response with count platforms,
// one of which is "imported-platform" so ListBy after Import finds it.
func mockTargetPlatformsBody(count int) string {
	platforms := make([]string, 0, count)
	if count > 0 {
		platforms = append(platforms, `{"id": 123, "platform_id": "imported-platform", "name": "Imported Platform"}`)
	}
	for len(platforms) < count {
		platforms = append(platforms, `{"id": 1, "platform_id": "p", "name": "p"}`)
	}
	return `{"platforms": [` + strings.Join(platforms, ",") + `]}`
}

// limitTestTenant simulates a tenant whose platform count grows with each successful import.
type limitTestTenant struct {
	serverCount atomic.Int64
	posts       atomic.Int64
	gets        atomic.Int64
}

func (tt *limitTestTenant) attach(service *IdsecPCloudTargetPlatformsService) {
	service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
		tt.gets.Add(1)
		return NewMockResponse(http.StatusOK, mockTargetPlatformsBody(int(tt.serverCount.Load()))), nil
	}
	service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
		tt.posts.Add(1)
		tt.serverCount.Add(1)
		return NewMockResponse(http.StatusCreated, `{"platform_id": "imported-platform"}`), nil
	}
	service.doDelete = func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
		tt.serverCount.Add(-1)
		return NewMockResponse(http.StatusNoContent, ""), nil
	}
}

func writeTestZip(t *testing.T) string {
	t.Helper()
	tmpFile := filepath.Join(t.TempDir(), "target-platform.zip")
	if err := os.WriteFile(tmpFile, []byte("fake zip content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	return tmpFile
}

// TestImportConcurrentRespectsLimit tests that parallel imports cannot exceed maxTargetPlatforms.
//
// Starting at 795 platforms, 10 concurrent imports must yield exactly 5 successes, and the
// platform list must be fetched once for the count instead of once per import.
func TestImportConcurrentRespectsLimit(t *testing.T) {
	tenant := &limitTestTenant{}
	tenant.serverCount.Store(maxTargetPlatforms - 5)
	service := createTestService()
	tenant.attach(service)
	zipPath := writeTestZip(t)

	var wg sync.WaitGroup
	var succeeded, limited atomic.Int64
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := service.Import(&targetplatformsmodels.IdsecPCloudImportTargetPlatform{PlatformZipPath: zipPath})
			switch {
			case err == nil:
				succeeded.Add(1)
			case strings.HasPrefix(err.Error(), "cannot import platform"):
				limited.Add(1)
			default:
				t.Errorf("Unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if succeeded.Load() != 5 || limited.Load() != 5 {
		t.Errorf("Expected 5 successes and 5 limit errors, got %d and %d", succeeded.Load(), limited.Load())
	}
	if tenant.posts.Load() != 5 {
		t.Errorf("Expected 5 import requests, got %d", tenant.posts.Load())
	}
	if tenant.serverCount.Load() != maxTargetPlatforms {
		t.Errorf("Expected tenant to end at %d platforms, got %d", maxTargetPlatforms, tenant.serverCount.Load())
	}
	// 1 initial count + 5 ListBy after successful imports + 5 re-counts before rejecting.
	if tenant.gets.Load() != 11 {
		t.Errorf("Expected 11 list requests, got %d", tenant.gets.Load())
	}
}

// TestImportCountRefresh tests that the cached count picks up platforms changed outside the service.
func TestImportCountRefresh(t *testing.T) {
	t.Run("deleted_elsewhere_detected_before_rejecting", func(t *testing.T) {
		tenant := &limitTestTenant{}
		tenant.serverCount.Store(maxTargetPlatforms - 1)
		service := createTestService()
		tenant.attach(service)
		clock := time.Unix(0, 0)
		service.now = func() time.Time { return clock }
		zipPath := writeTestZip(t)

		if _, err := service.Import(&targetplatformsmodels.IdsecPCloudImportTargetPlatform{PlatformZipPath: zipPath}); err != nil {
			t.Fatalf("Expected first import to succeed, got %v", err)
		}
		// Cache now says 800 and is still fresh; another client deletes 3 platforms.
		tenant.serverCount.Add(-3)
		if _, err := service.Import(&targetplatformsmodels.IdsecPCloudImportTargetPlatform{PlatformZipPath: zipPath}); err != nil {
			t.Errorf("Expected import to succeed after external deletions, got %v", err)
		}
	})

	t.Run("created_elsewhere_detected_after_interval", func(t *testing.T) {
		tenant := &limitTestTenant{}
		tenant.serverCount.Store(maxTargetPlatforms - 10)
		service := createTestService()
		tenant.attach(service)
		clock := time.Unix(0, 0)
		service.now = func() time.Time { return clock }
		zipPath := writeTestZip(t)

		if _, err := service.Import(&targetplatformsmodels.IdsecPCloudImportTargetPlatform{PlatformZipPath: zipPath}); err != nil {
			t.Fatalf("Expected first import to succeed, got %v", err)
		}
		// Another client fills the tenant; the cache (791) is stale once the interval passes.
		tenant.serverCount.Store(maxTargetPlatforms)
		clock = clock.Add(targetPlatformsCountRefreshInterval)
		_, err := service.Import(&targetplatformsmodels.IdsecPCloudImportTargetPlatform{PlatformZipPath: zipPath})
		if err == nil || !strings.HasPrefix(err.Error(), "cannot import platform") {
			t.Errorf("Expected limit error after refresh, got %v", err)
		}
		if tenant.posts.Load() != 1 {
			t.Errorf("Expected 1 import request, got %d", tenant.posts.Load())
		}
	})

	t.Run("fresh_cache_skips_list_request", func(t *testing.T) {
		tenant := &limitTestTenant{}
		tenant.serverCount.Store(10)
		service := createTestService()
		tenant.attach(service)
		clock := time.Unix(0, 0)
		service.now = func() time.Time { return clock }
		zipPath := writeTestZip(t)

		for i := 0; i < 3; i++ {
			if _, err := service.Import(&targetplatformsmodels.IdsecPCloudImportTargetPlatform{PlatformZipPath: zipPath}); err != nil {
				t.Fatalf("Expected import to succeed, got %v", err)
			}
		}
		// 1 count + 3 ListBy after imports.
		if tenant.gets.Load() != 4 {
			t.Errorf("Expected 4 list requests, got %d", tenant.gets.Load())
		}
	})

	t.Run("delete_frees_slot_in_cache", func(t *testing.T) {
		tenant := &limitTestTenant{}
		tenant.serverCount.Store(maxTargetPlatforms - 1)
		service := createTestService()
		tenant.attach(service)
		clock := time.Unix(0, 0)
		service.now = func() time.Time { return clock }
		zipPath := writeTestZip(t)

		if _, err := service.Import(&targetplatformsmodels.IdsecPCloudImportTargetPlatform{PlatformZipPath: zipPath}); err != nil {
			t.Fatalf("Expected first import to succeed, got %v", err)
		}
		id := 123
		if err := service.Delete(&targetplatformsmodels.IdsecPCloudDeleteTargetPlatform{ID: &id}); err != nil {
			t.Fatalf("Expected delete to succeed, got %v", err)
		}
		getsBefore := tenant.gets.Load()
		if _, err := service.Import(&targetplatformsmodels.IdsecPCloudImportTargetPlatform{PlatformZipPath: zipPath}); err != nil {
			t.Fatalf("Expected import after delete to succeed, got %v", err)
		}
		// Only the ListBy after import; the cached count was used for the limit check.
		if got := tenant.gets.Load() - getsBefore; got != 1 {
			t.Errorf("Expected 1 list request after delete, got %d", got)
		}
	})
}
