package db

import (
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	workspacesdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/models"
)

// TestAddDatabaseTarget_Validation tests validation errors in AddDatabaseTarget method.
//
// This test validates that the AddDatabaseTarget method properly validates input parameters
// and returns appropriate errors when mandatory fields are missing or invalid values are provided.
// Each test case checks a specific validation scenario to ensure comprehensive coverage.
//
// The test uses validation-only scenarios where errors are caught before HTTP calls are made,
// so no mock client is needed for these cases.
func TestAddDatabaseTarget_Validation(t *testing.T) {
	tests := []struct {
		name             string
		addDatabase      *workspacesdbmodels.IdsecSIADBAddDatabaseTarget
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "error_invalid_provider_engine",
			addDatabase: &workspacesdbmodels.IdsecSIADBAddDatabaseTarget{
				Name:              "test-db",
				ProviderEngine:    "invalid_engine",
				ReadWriteEndpoint: "db.example.com",
			},
			expectedError:    true,
			expectedErrorMsg: "invalid provider engine",
		},
		{
			name: "error_empty_provider_engine",
			addDatabase: &workspacesdbmodels.IdsecSIADBAddDatabaseTarget{
				Name:              "test-db",
				ProviderEngine:    "",
				ReadWriteEndpoint: "db.example.com",
			},
			expectedError:    true,
			expectedErrorMsg: "invalid provider engine",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// Initialize IdsecBaseService with Logger to prevent nil pointer dereference
			service := &IdsecSIAWorkspacesDBService{
				IdsecBaseService: &services.IdsecBaseService{
					Logger: common.GetLogger("TestAddDatabaseTarget", common.Info),
				},
			}

			// Execute the function
			_, err := service.AddDatabaseTarget(testCase.addDatabase)

			// Validate error expectation
			if testCase.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if testCase.expectedErrorMsg != "" && !strings.Contains(err.Error(), testCase.expectedErrorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", testCase.expectedErrorMsg, err.Error())
				}
				return
			}
		})
	}
}
