package db

import (
	"slices"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	workspacesdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacesdb/models"
)

// newTestService returns a service that can run the input validations performed before any
// request is issued.
func newTestService(name string) *IdsecSIAWorkspacesDBService {
	return &IdsecSIAWorkspacesDBService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GetLogger(name, common.Info),
		},
	}
}

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

			service := newTestService("TestAddDatabaseTarget")

			// Execute the function
			_, err := service.CreateTarget(testCase.addDatabase)

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

// TestListTargetFamilyTypes tests the database families reported for the database-onboarding new API.
//
// Every reported family is expected to be a known database family, while the families that cannot
// be onboarded through that API are expected not to be reported.
func TestListTargetFamilyTypes(t *testing.T) {
	t.Parallel()

	service := newTestService("TestListTargetFamilyTypes")

	targetFamilies, err := service.ListTargetFamilyTypes()
	if err != nil {
		t.Fatalf("Expected no error, got '%s'", err)
	}
	if len(targetFamilies) == 0 {
		t.Fatal("Expected at least one supported family, got none")
	}

	allFamilies, err := service.ListFamilyTypes()
	if err != nil {
		t.Fatalf("Expected no error, got '%s'", err)
	}
	for _, family := range targetFamilies {
		if !slices.Contains(allFamilies, family) {
			t.Errorf("Expected family '%s' to be a known database family", family)
		}
	}
	for _, family := range []string{"Unknown", "Cassandra"} {
		if slices.Contains(targetFamilies, family) {
			t.Errorf("Expected family '%s' not to be reported as supported", family)
		}
	}
}

// TestListTargetsBy_Validation tests validation errors in the ListTargetsBy method.
//
// This test validates that filtering by a database family or engine that cannot be onboarded
// through the database-onboarding new API is rejected before any HTTP call is made, so no mock
// client is needed for these cases.
func TestListTargetsBy_Validation(t *testing.T) {
	tests := []struct {
		name             string
		databasesFilter  *workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter
		expectedErrorMsg string
	}{
		{
			name:             "error_unsupported_provider_family",
			databasesFilter:  &workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{ProviderFamily: "Cassandra"},
			expectedErrorMsg: "invalid provider family",
		},
		{
			name:             "error_unknown_provider_family",
			databasesFilter:  &workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{ProviderFamily: "Unknown"},
			expectedErrorMsg: "invalid provider family",
		},
		{
			name:             "error_misspelled_provider_family",
			databasesFilter:  &workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{ProviderFamily: "mysql"},
			expectedErrorMsg: "invalid provider family",
		},
		{
			name:             "error_invalid_provider_engine",
			databasesFilter:  &workspacesdbmodels.IdsecSIADBDatabaseTargetsFilter{ProviderEngine: "invalid_engine"},
			expectedErrorMsg: "invalid provider engine",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			service := newTestService("TestListTargetsBy")

			_, err := service.ListTargetsBy(testCase.databasesFilter)

			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if !strings.Contains(err.Error(), testCase.expectedErrorMsg) {
				t.Errorf("Expected error message to contain '%s', got '%s'", testCase.expectedErrorMsg, err.Error())
			}
		})
	}
}
