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

// TestList tests the List method.
//
// This test validates the ability to list all platforms.
// It tests successful listing and various error conditions.
func TestList(t *testing.T) {
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
// This test validates filtering platforms by various criteria.
// It tests different filter combinations and error conditions.
func TestListBy(t *testing.T) {
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
// This test validates retrieval of a specific platform by ID.
// It tests successful retrieval and various error conditions.
func TestGet(t *testing.T) {
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

			result, err := service.Get(&platformsmodels.IdsecPCloudGetPlatform{PlatformID: tt.platformID})

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
// This test validates importing a platform from a zip file.
// It tests successful import and various error conditions.
func TestImport(t *testing.T) {
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
			_, err := service.Import(&platformsmodels.IdsecPCloudImportPlatform{
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
// This test validates exporting a platform to a zip file.
// It tests successful export and various error conditions.
func TestExport(t *testing.T) {
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
			err := service.Export(&platformsmodels.IdsecPCloudExportPlatform{
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

// TestStats tests the Stats method.
//
// This test validates platform statistics calculation.
// It tests successful stats generation and error conditions.
func TestStats(t *testing.T) {
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
