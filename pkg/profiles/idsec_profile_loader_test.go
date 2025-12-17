package profiles

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/models"
)

// createTempProfilesDir creates a temporary directory for testing profiles
func createTempProfilesDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "idsec_profiles_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	return tempDir
}

// createTestProfile creates a sample profile for testing
func createTestProfile(name string) *models.IdsecProfile {
	return &models.IdsecProfile{
		ProfileName: name,
	}
}

func TestDefaultProfileName(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult string
	}{
		{
			name:           "returns_default_profile_name",
			expectedResult: "idsec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := DefaultProfileName()

			if result != tt.expectedResult {
				t.Errorf("Expected DefaultProfileName() to return %s, got %s", tt.expectedResult, result)
			}
		})
	}
}

func TestGetProfilesFolder(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func() func() // Returns cleanup function
		expectedResult string
		validateFunc   func(t *testing.T, result string)
	}{
		{
			name: "returns_env_var_when_set",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", "/custom/path")
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedResult: "/custom/path",
		},
		{
			name: "returns_default_path_when_env_not_set",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Unsetenv("IDSEC_PROFILES_FOLDER")
				return func() {
					if originalValue != "" {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			validateFunc: func(t *testing.T, result string) {
				homeDir := os.Getenv("HOME")
				expectedPath := filepath.Join(homeDir, ".idsec_profiles")
				if result != expectedPath {
					t.Errorf("Expected default path %s, got %s", expectedPath, result)
				}
			},
		},
		{
			name: "returns_empty_env_var_when_empty",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", "")
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			validateFunc: func(t *testing.T, result string) {
				homeDir := os.Getenv("HOME")
				expectedPath := filepath.Join(homeDir, ".idsec_profiles")
				if result != expectedPath {
					t.Errorf("Expected default path when env var empty %s, got %s", expectedPath, result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				cleanup = tt.setupFunc()
			}
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()

			result := GetProfilesFolder()

			if tt.expectedResult != "" && result != tt.expectedResult {
				t.Errorf("Expected GetProfilesFolder() to return %s, got %s", tt.expectedResult, result)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestDeduceProfileName(t *testing.T) {
	tests := []struct {
		name           string
		profileName    string
		setupFunc      func() func() // Returns cleanup function
		expectedResult string
	}{
		{
			name:           "returns_provided_name_when_different_from_default",
			profileName:    "production",
			expectedResult: "production",
		},
		{
			name:        "returns_env_var_when_provided_name_empty",
			profileName: "",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILE")
				os.Setenv("IDSEC_PROFILE", "staging")
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILE")
					} else {
						os.Setenv("IDSEC_PROFILE", originalValue)
					}
				}
			},
			expectedResult: "staging",
		},
		{
			name:        "returns_env_var_when_provided_name_is_default",
			profileName: "idsec",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILE")
				os.Setenv("IDSEC_PROFILE", "development")
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILE")
					} else {
						os.Setenv("IDSEC_PROFILE", originalValue)
					}
				}
			},
			expectedResult: "development",
		},
		{
			name:        "returns_provided_name_when_env_not_set",
			profileName: "test",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILE")
				os.Unsetenv("IDSEC_PROFILE")
				return func() {
					if originalValue != "" {
						os.Setenv("IDSEC_PROFILE", originalValue)
					}
				}
			},
			expectedResult: "test",
		},
		{
			name:        "returns_default_when_no_name_and_no_env",
			profileName: "",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILE")
				os.Unsetenv("IDSEC_PROFILE")
				return func() {
					if originalValue != "" {
						os.Setenv("IDSEC_PROFILE", originalValue)
					}
				}
			},
			expectedResult: "idsec",
		},
		{
			name:        "returns_default_name_when_provided_as_default",
			profileName: "idsec",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILE")
				os.Unsetenv("IDSEC_PROFILE")
				return func() {
					if originalValue != "" {
						os.Setenv("IDSEC_PROFILE", originalValue)
					}
				}
			},
			expectedResult: "idsec",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				cleanup = tt.setupFunc()
			}
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()

			result := DeduceProfileName(tt.profileName)

			if result != tt.expectedResult {
				t.Errorf("Expected DeduceProfileName(%s) to return %s, got %s", tt.profileName, tt.expectedResult, result)
			}
		})
	}
}

func TestDefaultProfilesLoader(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, result *ProfileLoader)
	}{
		{
			name: "returns_filesystem_loader",
			validateFunc: func(t *testing.T, result *ProfileLoader) {
				if result == nil {
					t.Error("Expected non-nil ProfileLoader")
					return
				}
				// Check that it's actually a FileSystemProfilesLoader
				if _, ok := (*result).(*FileSystemProfilesLoader); !ok {
					t.Error("Expected FileSystemProfilesLoader implementation")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := DefaultProfilesLoader()

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestFileSystemProfilesLoader_ProfileExists(t *testing.T) {
	tempDir := createTempProfilesDir(t)
	defer os.RemoveAll(tempDir)

	// Create a test profile file
	testProfile := createTestProfile("test-profile")
	profileData, _ := json.Marshal(testProfile)
	profilePath := filepath.Join(tempDir, "test-profile")
	err := os.WriteFile(profilePath, profileData, 0644)
	if err != nil {
		t.Fatalf("Failed to create test profile file: %v", err)
	}

	tests := []struct {
		name           string
		profileName    string
		setupFunc      func() func() // Returns cleanup function
		expectedResult bool
	}{
		{
			name:        "returns_true_when_profile_exists",
			profileName: "test-profile",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedResult: true,
		},
		{
			name:        "returns_false_when_profile_does_not_exist",
			profileName: "nonexistent-profile",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				cleanup = tt.setupFunc()
			}
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()

			loader := &FileSystemProfilesLoader{}
			result := loader.ProfileExists(tt.profileName)

			if result != tt.expectedResult {
				t.Errorf("Expected ProfileExists(%s) to return %v, got %v", tt.profileName, tt.expectedResult, result)
			}
		})
	}
}

func TestFileSystemProfilesLoader_SaveProfile(t *testing.T) {
	tempDir := createTempProfilesDir(t)
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name          string
		profile       *models.IdsecProfile
		setupFunc     func() func() // Returns cleanup function
		expectedError bool
		validateFunc  func(t *testing.T, tempDir string)
	}{
		{
			name:    "success_saves_profile",
			profile: createTestProfile("test-save"),
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, tempDir string) {
				profilePath := filepath.Join(tempDir, "test-save")
				if _, err := os.Stat(profilePath); os.IsNotExist(err) {
					t.Error("Expected profile file to be created")
				}
			},
		},
		{
			name:    "success_creates_directory_if_not_exists",
			profile: createTestProfile("test-mkdir"),
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				// Use a subdirectory that doesn't exist
				nonExistentDir := filepath.Join(tempDir, "nonexistent")
				os.Setenv("IDSEC_PROFILES_FOLDER", nonExistentDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, tempDir string) {
				nonExistentDir := filepath.Join(tempDir, "nonexistent")
				profilePath := filepath.Join(nonExistentDir, "test-mkdir")
				if _, err := os.Stat(profilePath); os.IsNotExist(err) {
					t.Error("Expected profile file to be created in new directory")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				cleanup = tt.setupFunc()
			}
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()

			loader := &FileSystemProfilesLoader{}
			err := loader.SaveProfile(tt.profile)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, tempDir)
			}
		})
	}
}

func TestFileSystemProfilesLoader_LoadProfile(t *testing.T) {
	tempDir := createTempProfilesDir(t)
	defer os.RemoveAll(tempDir)

	// Create a test profile file
	testProfile := createTestProfile("test-load")
	profileData, _ := json.MarshalIndent(testProfile, "", "    ")
	profilePath := filepath.Join(tempDir, "test-load")
	err := os.WriteFile(profilePath, profileData, 0644)
	if err != nil {
		t.Fatalf("Failed to create test profile file: %v", err)
	}

	tests := []struct {
		name           string
		profileName    string
		setupFunc      func() func() // Returns cleanup function
		expectedError  bool
		expectedResult *models.IdsecProfile
		validateFunc   func(t *testing.T, result *models.IdsecProfile)
	}{
		{
			name:        "success_loads_existing_profile",
			profileName: "test-load",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *models.IdsecProfile) {
				if result == nil {
					t.Error("Expected non-nil profile")
					return
				}
				if result.ProfileName != "test-load" {
					t.Errorf("Expected profile name 'test-load', got '%s'", result.ProfileName)
				}
			},
		},
		{
			name:        "returns_nil_when_profile_does_not_exist",
			profileName: "nonexistent",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *models.IdsecProfile) {
				if result != nil {
					t.Error("Expected nil profile for nonexistent profile")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				cleanup = tt.setupFunc()
			}
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()

			loader := &FileSystemProfilesLoader{}
			result, err := loader.LoadProfile(tt.profileName)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.expectedResult != nil && !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("Expected result %+v, got %+v", tt.expectedResult, result)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestFileSystemProfilesLoader_LoadDefaultProfile(t *testing.T) {
	tempDir := createTempProfilesDir(t)
	defer os.RemoveAll(tempDir)

	// Create a default profile file
	defaultProfile := createTestProfile("idsec")
	profileData, _ := json.MarshalIndent(defaultProfile, "", "    ")
	profilePath := filepath.Join(tempDir, "idsec")
	err := os.WriteFile(profilePath, profileData, 0644)
	if err != nil {
		t.Fatalf("Failed to create default profile file: %v", err)
	}

	tests := []struct {
		name          string
		setupFunc     func() func() // Returns cleanup function
		expectedError bool
		validateFunc  func(t *testing.T, result *models.IdsecProfile)
	}{
		{
			name: "success_loads_default_profile",
			setupFunc: func() func() {
				originalFolder := os.Getenv("IDSEC_PROFILES_FOLDER")
				originalProfile := os.Getenv("IDSEC_PROFILE")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				os.Unsetenv("IDSEC_PROFILE")
				return func() {
					if originalFolder == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalFolder)
					}
					if originalProfile != "" {
						os.Setenv("IDSEC_PROFILE", originalProfile)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *models.IdsecProfile) {
				if result == nil {
					t.Error("Expected non-nil profile")
					return
				}
				if result.ProfileName != "idsec" {
					t.Errorf("Expected profile name 'idsec', got '%s'", result.ProfileName)
				}
			},
		},
		{
			name: "returns_empty_profile_when_default_does_not_exist",
			setupFunc: func() func() {
				originalFolder := os.Getenv("IDSEC_PROFILES_FOLDER")
				originalProfile := os.Getenv("IDSEC_PROFILE")
				// Use a different temp directory where no profile exists
				emptyDir := createTempProfilesDir(t)
				os.Setenv("IDSEC_PROFILES_FOLDER", emptyDir)
				os.Unsetenv("IDSEC_PROFILE")
				return func() {
					os.RemoveAll(emptyDir)
					if originalFolder == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalFolder)
					}
					if originalProfile != "" {
						os.Setenv("IDSEC_PROFILE", originalProfile)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result *models.IdsecProfile) {
				if result == nil {
					t.Error("Expected non-nil empty profile")
					return
				}
				// Should return empty profile struct
				if result.ProfileName != "" {
					t.Errorf("Expected empty profile name, got '%s'", result.ProfileName)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				cleanup = tt.setupFunc()
			}
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()

			loader := &FileSystemProfilesLoader{}
			result, err := loader.LoadDefaultProfile()

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestFileSystemProfilesLoader_DeleteProfile(t *testing.T) {
	tempDir := createTempProfilesDir(t)
	defer os.RemoveAll(tempDir)

	// Create a test profile file to delete
	testProfile := createTestProfile("test-delete")
	profileData, _ := json.Marshal(testProfile)
	profilePath := filepath.Join(tempDir, "test-delete")
	err := os.WriteFile(profilePath, profileData, 0644)
	if err != nil {
		t.Fatalf("Failed to create test profile file: %v", err)
	}

	tests := []struct {
		name          string
		profileName   string
		setupFunc     func() func() // Returns cleanup function
		expectedError bool
		validateFunc  func(t *testing.T, tempDir string)
	}{
		{
			name:        "success_deletes_existing_profile",
			profileName: "test-delete",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, tempDir string) {
				profilePath := filepath.Join(tempDir, "test-delete")
				if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
					t.Error("Expected profile file to be deleted")
				}
			},
		},
		{
			name:        "success_idempotent_when_profile_does_not_exist",
			profileName: "nonexistent",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				cleanup = tt.setupFunc()
			}
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()

			loader := &FileSystemProfilesLoader{}
			err := loader.DeleteProfile(tt.profileName)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, tempDir)
			}
		})
	}
}

func TestFileSystemProfilesLoader_LoadAllProfiles(t *testing.T) {
	tempDir := createTempProfilesDir(t)
	defer os.RemoveAll(tempDir)

	// Create multiple test profile files
	profiles := []string{"profile1", "profile2", "profile3"}
	for _, profileName := range profiles {
		testProfile := createTestProfile(profileName)
		profileData, _ := json.MarshalIndent(testProfile, "", "    ")
		profilePath := filepath.Join(tempDir, profileName)
		err := os.WriteFile(profilePath, profileData, 0644)
		if err != nil {
			t.Fatalf("Failed to create test profile file %s: %v", profileName, err)
		}
	}

	// Create a subdirectory (should be ignored)
	err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	tests := []struct {
		name          string
		setupFunc     func() func() // Returns cleanup function
		expectedError bool
		validateFunc  func(t *testing.T, result []*models.IdsecProfile)
	}{
		{
			name: "success_loads_all_profiles",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result []*models.IdsecProfile) {
				if len(result) != 3 {
					t.Errorf("Expected 3 profiles, got %d", len(result))
					return
				}
				// Check that all expected profiles are present
				foundProfiles := make(map[string]bool)
				for _, profile := range result {
					foundProfiles[profile.ProfileName] = true
				}
				for _, expectedName := range profiles {
					if !foundProfiles[expectedName] {
						t.Errorf("Expected to find profile %s", expectedName)
					}
				}
			},
		},
		{
			name: "returns_nil_when_directory_does_not_exist",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", "/nonexistent/directory")
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, result []*models.IdsecProfile) {
				if result != nil {
					t.Error("Expected nil result for nonexistent directory")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				cleanup = tt.setupFunc()
			}
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()

			loader := &FileSystemProfilesLoader{}
			result, err := loader.LoadAllProfiles()

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestFileSystemProfilesLoader_ClearAllProfiles(t *testing.T) {
	tempDir := createTempProfilesDir(t)
	defer os.RemoveAll(tempDir)

	// Create multiple test profile files
	profiles := []string{"profile1", "profile2", "profile3"}
	for _, profileName := range profiles {
		testProfile := createTestProfile(profileName)
		profileData, _ := json.MarshalIndent(testProfile, "", "    ")
		profilePath := filepath.Join(tempDir, profileName)
		err := os.WriteFile(profilePath, profileData, 0644)
		if err != nil {
			t.Fatalf("Failed to create test profile file %s: %v", profileName, err)
		}
	}

	// Create a subdirectory (should be left intact)
	subDir := filepath.Join(tempDir, "subdir")
	err := os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	tests := []struct {
		name          string
		setupFunc     func() func() // Returns cleanup function
		expectedError bool
		validateFunc  func(t *testing.T, tempDir string)
	}{
		{
			name: "success_clears_all_profiles",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", tempDir)
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, tempDir string) {
				// Check that profile files are deleted
				for _, profileName := range profiles {
					profilePath := filepath.Join(tempDir, profileName)
					if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
						t.Errorf("Expected profile file %s to be deleted", profileName)
					}
				}
				// Check that subdirectory is still there
				if _, err := os.Stat(subDir); os.IsNotExist(err) {
					t.Error("Expected subdirectory to remain intact")
				}
			},
		},
		{
			name: "success_idempotent_when_directory_does_not_exist",
			setupFunc: func() func() {
				originalValue := os.Getenv("IDSEC_PROFILES_FOLDER")
				os.Setenv("IDSEC_PROFILES_FOLDER", "/nonexistent/directory")
				return func() {
					if originalValue == "" {
						os.Unsetenv("IDSEC_PROFILES_FOLDER")
					} else {
						os.Setenv("IDSEC_PROFILES_FOLDER", originalValue)
					}
				}
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleanup func()
			if tt.setupFunc != nil {
				cleanup = tt.setupFunc()
			}
			defer func() {
				if cleanup != nil {
					cleanup()
				}
			}()

			loader := &FileSystemProfilesLoader{}
			err := loader.ClearAllProfiles()

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, tempDir)
			}
		})
	}
}
