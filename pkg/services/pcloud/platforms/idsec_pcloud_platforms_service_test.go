package platforms

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
	platformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms/models"
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
func createTestService() *IdsecPCloudPlatformsService {
	service := &IdsecPCloudPlatformsService{}
	service.IdsecBaseService = &services.IdsecBaseService{
		Logger: common.GetLogger("test", common.Unknown),
	}
	return service
}

// TestListPlatforms tests the ListPlatforms method.
//
// This test validates the ability to list all platforms.
// It tests successful listing and various error conditions.
func TestListPlatforms(t *testing.T) {
	mockPlatformsList := `{
		"platforms": [
			{
				"general": {
					"id": "platform-1",
					"name": "Test Platform 1",
					"platform_type": "unix"
				}
			},
			{
				"general": {
					"id": "platform-2",
					"name": "Test Platform 2",
					"platform_type": "windows"
				}
			}
		]
	}`

	tests := []struct {
		name             string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result []*platformsmodels.IdsecPCloudPlatform)
	}{
		{
			name:           "success_list_all_platforms",
			mockStatusCode: http.StatusOK,
			mockBody:       mockPlatformsList,
			expectedError:  false,
			validateFunc: func(t *testing.T, result []*platformsmodels.IdsecPCloudPlatform) {
				if len(result) != 2 {
					t.Errorf("Expected 2 platforms, got %d", len(result))
				}
			},
		},
		{
			name:           "success_empty_list",
			mockStatusCode: http.StatusOK,
			mockBody:       `{"platforms": []}`,
			expectedError:  false,
			validateFunc: func(t *testing.T, result []*platformsmodels.IdsecPCloudPlatform) {
				if len(result) != 0 {
					t.Errorf("Expected 0 platforms, got %d", len(result))
				}
			},
		},
		{
			name:             "error_unauthorized",
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list platforms",
		},
		{
			name:             "error_bad_request",
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "bad request"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list platforms",
		},
		{
			name:             "error_internal_server",
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list platforms",
		},
		{
			name:             "error_invalid_response",
			mockStatusCode:   http.StatusOK,
			mockBody:         `{"invalid": "response"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list platforms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.ListPlatforms()

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

// TestListPlatformsBy tests the ListPlatformsBy method.
//
// This test validates filtering platforms by various criteria.
// It tests different filter combinations and error conditions.
func TestListPlatformsBy(t *testing.T) {
	mockPlatformsList := `{
		"platforms": [
			{
				"general": {
					"id": "unix-platform",
					"name": "Unix Platform",
					"platform_type": "unix"
				}
			},
			{
				"general": {
					"id": "windows-platform",
					"name": "Windows Platform",
					"platform_type": "windows"
				}
			}
		]
	}`

	tests := []struct {
		name             string
		filter           *platformsmodels.IdsecPCloudPlatformsFilter
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result []*platformsmodels.IdsecPCloudPlatform)
	}{
		{
			name: "success_filter_by_platform_type",
			filter: &platformsmodels.IdsecPCloudPlatformsFilter{
				PlatformType: "unix",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_filter_by_platform_name",
			filter: &platformsmodels.IdsecPCloudPlatformsFilter{
				PlatformName: "Unix Platform",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_filter_by_active",
			filter: &platformsmodels.IdsecPCloudPlatformsFilter{
				Active: true,
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_multiple_filters",
			filter: &platformsmodels.IdsecPCloudPlatformsFilter{
				Active:       true,
				PlatformType: "unix",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockPlatformsList,
			expectedError:  false,
		},
		{
			name:             "error_unauthorized",
			filter:           &platformsmodels.IdsecPCloudPlatformsFilter{},
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list platforms",
		},
		{
			name:             "error_internal_server",
			filter:           &platformsmodels.IdsecPCloudPlatformsFilter{},
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list platforms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.ListPlatformsBy(tt.filter)

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

// TestPlatform tests the Platform method.
//
// This test validates retrieval of a specific platform by ID.
// It tests successful retrieval and various error conditions.
func TestPlatform(t *testing.T) {
	mockPlatform := `{
		"general": {
			"id": "platform-123",
			"name": "Test Platform",
			"platform_type": "unix"
		}
	}`

	tests := []struct {
		name             string
		platformID       string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *platformsmodels.IdsecPCloudPlatformDetails)
	}{
		{
			name:           "success_get_platform",
			platformID:     "platform-123",
			mockStatusCode: http.StatusOK,
			mockBody:       mockPlatform,
			expectedError:  false,
		},
		{
			name:             "error_not_found",
			platformID:       "nonexistent",
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "platform not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to retrieve platform",
		},
		{
			name:             "error_unauthorized",
			platformID:       "platform-123",
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to retrieve platform",
		},
		{
			name:             "error_forbidden",
			platformID:       "platform-123",
			mockStatusCode:   http.StatusForbidden,
			mockBody:         `{"error": "forbidden"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to retrieve platform",
		},
		{
			name:             "error_internal_server",
			platformID:       "platform-123",
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to retrieve platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.Platform(&platformsmodels.IdsecPCloudGetPlatform{PlatformID: tt.platformID})

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

// TestImportPlatform tests the ImportPlatform method.
//
// This test validates importing a platform from a zip file.
// It tests successful import and various error conditions.
func TestImportPlatform(t *testing.T) {
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
			name: "success_import_platform",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "platform.zip")
				err := os.WriteFile(tmpFile, []byte("fake zip content"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockStatusCode: http.StatusCreated,
			mockBody:       `{"platform_id": "platform-123"}`,
			mockGetBody:    `{"general": {"id": "platform-123"}}`,
			expectedError:  false,
		},
		{
			name: "error_file_not_found",
			setupFile: func(t *testing.T) string {
				return "/nonexistent/platform.zip"
			},
			expectedError:    true,
			expectedErrorMsg: "given path",
		},
		{
			name: "error_bad_request",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "platform.zip")
				err := os.WriteFile(tmpFile, []byte("invalid content"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "invalid zip file"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to import platform",
		},
		{
			name: "error_unauthorized",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "platform.zip")
				err := os.WriteFile(tmpFile, []byte("fake zip content"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to import platform",
		},
		{
			name: "error_conflict",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "platform.zip")
				err := os.WriteFile(tmpFile, []byte("fake zip content"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockStatusCode:   http.StatusConflict,
			mockBody:         `{"error": "platform already exists"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to import platform",
		},
		{
			name: "error_internal_server",
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "platform.zip")
				err := os.WriteFile(tmpFile, []byte("fake zip content"), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to import platform",
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
			_, err := service.ImportPlatform(&platformsmodels.IdsecPCloudImportPlatform{
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

// TestExportPlatform tests the ExportPlatform method.
//
// This test validates exporting a platform to a zip file.
// It tests successful export and various error conditions.
func TestExportPlatform(t *testing.T) {
	tests := []struct {
		name             string
		platformID       string
		outputFolder     string
		setupFolder      func(t *testing.T) string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:       "success_export_platform",
			platformID: "platform-123",
			setupFolder: func(t *testing.T) string {
				return t.TempDir()
			},
			mockStatusCode: http.StatusOK,
			mockBody:       "fake zip content",
			expectedError:  false,
		},
		{
			name:       "error_platform_not_found",
			platformID: "nonexistent",
			setupFolder: func(t *testing.T) string {
				return t.TempDir()
			},
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "platform not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to export platform",
		},
		{
			name:       "error_unauthorized",
			platformID: "platform-123",
			setupFolder: func(t *testing.T) string {
				return t.TempDir()
			},
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to export platform",
		},
		{
			name:       "error_forbidden",
			platformID: "platform-123",
			setupFolder: func(t *testing.T) string {
				return t.TempDir()
			},
			mockStatusCode:   http.StatusForbidden,
			mockBody:         `{"error": "forbidden"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to export platform",
		},
		{
			name:       "error_internal_server",
			platformID: "platform-123",
			setupFolder: func(t *testing.T) string {
				return t.TempDir()
			},
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to export platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			outputFolder := tt.setupFolder(t)
			err := service.ExportPlatform(&platformsmodels.IdsecPCloudExportPlatform{
				PlatformID:   tt.platformID,
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

// TestPlatformsStats tests the PlatformsStats method.
//
// This test validates platform statistics calculation.
// It tests successful stats generation and error conditions.
func TestPlatformsStats(t *testing.T) {
	tests := []struct {
		name             string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *platformsmodels.IdsecPCloudPlatformsStats)
	}{
		{
			name:           "success_calculate_stats",
			mockStatusCode: http.StatusOK,
			mockBody: `{
				"platforms": [
					{"general": {"platform_type": "unix"}},
					{"general": {"platform_type": "windows"}},
					{"general": {"platform_type": "unix"}}
				]
			}`,
			expectedError: false,
			validateFunc: func(t *testing.T, result *platformsmodels.IdsecPCloudPlatformsStats) {
				if result.PlatformsCount != 3 {
					t.Errorf("Expected 3 platforms, got %d", result.PlatformsCount)
				}
				if result.PlatformsCountByType["unix"] != 2 {
					t.Errorf("Expected 2 unix platforms, got %d", result.PlatformsCountByType["unix"])
				}
			},
		},
		{
			name:           "success_empty_platforms",
			mockStatusCode: http.StatusOK,
			mockBody:       `{"platforms": []}`,
			expectedError:  false,
			validateFunc: func(t *testing.T, result *platformsmodels.IdsecPCloudPlatformsStats) {
				if result.PlatformsCount != 0 {
					t.Errorf("Expected 0 platforms, got %d", result.PlatformsCount)
				}
			},
		},
		{
			name:             "error_unauthorized",
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list platforms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.PlatformsStats()

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

// TestListTargetPlatforms tests the ListTargetPlatforms method.
//
// This test validates listing all target platforms.
// It tests successful listing and various error conditions.
func TestListTargetPlatforms(t *testing.T) {
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
		validateFunc     func(t *testing.T, result []*platformsmodels.IdsecPCloudTargetPlatform)
	}{
		{
			name:           "success_list_all_target_platforms",
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
			validateFunc: func(t *testing.T, result []*platformsmodels.IdsecPCloudTargetPlatform) {
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
			validateFunc: func(t *testing.T, result []*platformsmodels.IdsecPCloudTargetPlatform) {
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

			result, err := service.ListTargetPlatforms()

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

// TestListTargetPlatformsBy tests the ListTargetPlatformsBy method.
//
// This test validates filtering target platforms by various criteria.
// It tests different filter combinations and error conditions.
func TestListTargetPlatformsBy(t *testing.T) {
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
		filter           *platformsmodels.IdsecPCloudTargetPlatformsFilter
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result []*platformsmodels.IdsecPCloudTargetPlatform)
	}{
		{
			name: "success_filter_by_system_type",
			filter: &platformsmodels.IdsecPCloudTargetPlatformsFilter{
				SystemType: "Unix",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_filter_by_active",
			filter: &platformsmodels.IdsecPCloudTargetPlatformsFilter{
				Active: true,
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_filter_by_platform_id",
			filter: &platformsmodels.IdsecPCloudTargetPlatformsFilter{
				PlatformID: "target-unix-*",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_filter_by_name",
			filter: &platformsmodels.IdsecPCloudTargetPlatformsFilter{
				Name: "Unix*",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockTargetPlatformsList,
			expectedError:  false,
		},
		{
			name: "success_multiple_filters",
			filter: &platformsmodels.IdsecPCloudTargetPlatformsFilter{
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
			filter:           &platformsmodels.IdsecPCloudTargetPlatformsFilter{},
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

			result, err := service.ListTargetPlatformsBy(tt.filter)

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

// TestTargetPlatform tests the TargetPlatform method.
//
// This test validates retrieval of a specific target platform by ID.
// It tests successful retrieval and various error conditions.
func TestTargetPlatform(t *testing.T) {
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

			result, err := service.TargetPlatform(&platformsmodels.IdsecPCloudGetTargetPlatform{
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

// TestActivateTargetPlatform tests the ActivateTargetPlatform method.
//
// This test validates activating a target platform by ID.
// It tests successful activation and various error conditions.
func TestActivateTargetPlatform(t *testing.T) {
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

			err := service.ActivateTargetPlatform(&platformsmodels.IdsecPCloudActivateTargetPlatform{
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

// TestDeactivateTargetPlatform tests the DeactivateTargetPlatform method.
//
// This test validates deactivating a target platform by ID.
// It tests successful deactivation and various error conditions.
func TestDeactivateTargetPlatform(t *testing.T) {
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

			err := service.DeactivateTargetPlatform(&platformsmodels.IdsecPCloudDeactivateTargetPlatform{
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

// TestDuplicateTargetPlatform tests the DuplicateTargetPlatform method.
//
// This test validates duplicating a target platform by ID.
// It tests successful duplication and various error conditions.
func TestDuplicateTargetPlatform(t *testing.T) {
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

			result, err := service.DuplicateTargetPlatform(&platformsmodels.IdsecPCloudDuplicateTargetPlatform{
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

// TestDeleteTargetPlatform tests the DeleteTargetPlatform method.
//
// This test validates deleting a target platform by ID.
// It tests successful deletion and various error conditions.
func TestDeleteTargetPlatform(t *testing.T) {
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

			err := service.DeleteTargetPlatform(&platformsmodels.IdsecPCloudDeleteTargetPlatform{
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

// TestTargetPlatformsStats tests the TargetPlatformsStats method.
//
// This test validates target platform statistics calculation.
// It tests successful stats generation and error conditions.
func TestTargetPlatformsStats(t *testing.T) {
	tests := []struct {
		name             string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *platformsmodels.IdsecPCloudTargetPlatformsStats)
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
			validateFunc: func(t *testing.T, result *platformsmodels.IdsecPCloudTargetPlatformsStats) {
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
			validateFunc: func(t *testing.T, result *platformsmodels.IdsecPCloudTargetPlatformsStats) {
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

			result, err := service.TargetPlatformsStats()

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

// TestImportTargetPlatform tests the ImportTargetPlatform method.
//
// This test validates importing a target platform from a zip file.
// It tests successful import and various error conditions.
func TestImportTargetPlatform(t *testing.T) {
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
			_, err := service.ImportTargetPlatform(&platformsmodels.IdsecPCloudImportTargetPlatform{
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

// TestExportTargetPlatform tests the ExportTargetPlatform method.
//
// This test validates exporting a target platform to a zip file.
// It tests successful export and various error conditions.
func TestExportTargetPlatform(t *testing.T) {
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
			mockStatusCode: http.StatusOK,
			mockBody:       "",
			mockGetBody:    `{"platforms": []}`,
			expectedError:  true,
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
			err := service.ExportTargetPlatform(&platformsmodels.IdsecPCloudExportTargetPlatform{
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
