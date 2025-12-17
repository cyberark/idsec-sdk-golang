package vmsecrets

import (
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	vmsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm/models"
)

// TestListSecretsBy tests the client-side filtering functionality of ListSecretsBy method.
//
// This test validates the actual filtering logic in IdsecSIASecretsVMService.ListSecretsBy()
// by providing mock secrets data and verifying that the service's client-side filtering
// produces the expected results based on the manual test guide.
//
// Tests cover all scenarios from LIST_SECRETS_BY_MANUAL_TEST_GUIDE.md including:
// - Filtering by secret type (ProvisionerUser, PCloudAccount)
// - Filtering by name patterns using regex
// - Filtering by active/inactive status
// - Filtering by account domain with regex support
// - Combining multiple filters (AND logic)
// - Error cases (invalid secret types, invalid regex patterns)
func TestListSecretsBy(t *testing.T) {
	tests := []struct {
		name              string
		mockSecrets       []*vmsecretsmodels.IdsecSIAVMSecret
		filter            *vmsecretsmodels.IdsecSIAVMSecretsFilter
		expectedSecretIDs []string // Expected secret IDs in result
		expectedError     bool
		expectedErrorMsg  string
	}{
		{
			name: "success_filter_by_secret_type_provisioner_user",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "PCloudAccount",
					SecretName:    "test-pcloud",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-3",
					SecretType:    "ProvisionerUser",
					SecretName:    "another-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				SecretType: "ProvisionerUser",
			},
			expectedSecretIDs: []string{"secret-1", "secret-3"},
			expectedError:     false,
		},
		{
			name: "success_filter_by_secret_type_pcloud_account",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "PCloudAccount",
					SecretName:    "test-pcloud",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "another-pcloud",
					IsActive:      false,
					SecretDetails: map[string]interface{}{"account_domain": "domain"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				SecretType: "PCloudAccount",
			},
			expectedSecretIDs: []string{"secret-2", "secret-3"},
			expectedError:     false,
		},
		{
			name: "success_filter_by_name_pattern_exact_match",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-local-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-domain-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-3",
					SecretType:    "ProvisionerUser",
					SecretName:    "other-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				Name: "^test-local-provisioner$",
			},
			expectedSecretIDs: []string{"secret-1"},
			expectedError:     false,
		},
		{
			name: "success_filter_by_name_pattern_prefix_match",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-local-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-domain-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-3",
					SecretType:    "ProvisionerUser",
					SecretName:    "other-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				Name: "test",
			},
			expectedSecretIDs: []string{"secret-1", "secret-2"},
			expectedError:     false,
		},
		{
			name: "success_filter_by_is_active_true",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "active-secret-1",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "inactive-secret",
					IsActive:      false,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "active-secret-2",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				IsActive: "true",
			},
			expectedSecretIDs: []string{"secret-1", "secret-3"},
			expectedError:     false,
		},
		{
			name: "success_filter_by_is_active_false",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "active-secret",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "inactive-secret-1",
					IsActive:      false,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "inactive-secret-2",
					IsActive:      false,
					SecretDetails: map[string]interface{}{"account_domain": "domain"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				IsActive: "false",
			},
			expectedSecretIDs: []string{"secret-2", "secret-3"},
			expectedError:     false,
		},
		{
			name: "success_filter_by_account_domain_exact",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "local-secret",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "domain-secret",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "MYDOMAIN"},
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "another-local-secret",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				AccountDomain: "local",
			},
			expectedSecretIDs: []string{"secret-1", "secret-3"},
			expectedError:     false,
		},
		{
			name: "success_filter_by_account_domain_regex_pattern",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "local-secret",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "domain-secret",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "MYDOMAIN"},
				},
				{
					SecretID:      "secret-3",
					SecretType:    "ProvisionerUser",
					SecretName:    "otherdomain-secret",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "OTHERDOMAIN"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				AccountDomain: ".*DOMAIN.*",
			},
			expectedSecretIDs: []string{"secret-2", "secret-3"},
			expectedError:     false,
		},
		{
			name: "success_combine_multiple_filters",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-local-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-domain-provisioner",
					IsActive:      false,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "test-pcloud",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-4",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-active-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "DOMAIN"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				SecretType:    "ProvisionerUser",
				Name:          "test",
				IsActive:      "true",
				AccountDomain: "local",
			},
			expectedSecretIDs: []string{"secret-1"},
			expectedError:     false,
		},
		{
			name: "success_no_matches_returns_empty_array",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				Name: "nonexistent-secret-name-xyz",
			},
			expectedSecretIDs: []string{},
			expectedError:     false,
		},
		{
			name: "success_empty_filter_returns_all_secrets",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "PCloudAccount",
					SecretName:    "test-pcloud",
					IsActive:      false,
					SecretDetails: map[string]interface{}{"account_domain": "domain"},
				},
			},
			filter:            &vmsecretsmodels.IdsecSIAVMSecretsFilter{},
			expectedSecretIDs: []string{"secret-1", "secret-2"},
			expectedError:     false,
		},
		{
			name: "success_filter_by_account_domain_case_sensitive",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "secret-lowercase",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "secret-uppercase",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "LOCAL"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				AccountDomain: "local",
			},
			expectedSecretIDs: []string{"secret-1"},
			expectedError:     false,
		},
		{
			name: "success_filter_secret_with_missing_account_domain",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "secret-with-domain",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "secret-without-domain",
					IsActive:      true,
					SecretDetails: map[string]interface{}{},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				AccountDomain: "local",
			},
			expectedSecretIDs: []string{"secret-1"},
			expectedError:     false,
		},
		{
			name: "success_filter_is_active_case_insensitive",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "active-secret",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "inactive-secret",
					IsActive:      false,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				IsActive: "TRUE",
			},
			expectedSecretIDs: []string{"secret-1"},
			expectedError:     false,
		},
		{
			name: "error_invalid_secret_type",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				SecretType: "InvalidType",
			},
			expectedSecretIDs: nil,
			expectedError:     true,
			expectedErrorMsg:  "invalid secret type 'InvalidType'",
		},
		{
			name: "error_invalid_is_active_value",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				IsActive: "invalid",
			},
			expectedSecretIDs: nil,
			expectedError:     true,
			expectedErrorMsg:  "invalid is-active value 'invalid'",
		},
		{
			name: "error_invalid_name_regex_pattern",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				Name: "[invalid-regex",
			},
			expectedSecretIDs: nil,
			expectedError:     true,
			expectedErrorMsg:  "invalid name regex pattern",
		},
		{
			name: "error_invalid_account_domain_regex_pattern",
			mockSecrets: []*vmsecretsmodels.IdsecSIAVMSecret{
				{
					SecretID:      "secret-1",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-provisioner",
					IsActive:      true,
					SecretDetails: map[string]interface{}{"account_domain": "local"},
				},
			},
			filter: &vmsecretsmodels.IdsecSIAVMSecretsFilter{
				AccountDomain: "[invalid-regex",
			},
			expectedSecretIDs: nil,
			expectedError:     true,
			expectedErrorMsg:  "invalid account-domain regex pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create service with mock data
			service := createTestService(tt.mockSecrets)

			// Execute the REAL filtering logic from the service
			result, err := service.ListSecretsBy(tt.filter)

			// Validate error expectation
			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			// Validate no error when success expected
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Extract secret IDs from result
			var actualSecretIDs []string
			for _, secret := range result {
				actualSecretIDs = append(actualSecretIDs, secret.SecretID)
			}

			// Validate result count matches expected
			if len(actualSecretIDs) != len(tt.expectedSecretIDs) {
				t.Errorf("Expected %d secret IDs %v, got %d %v", len(tt.expectedSecretIDs), tt.expectedSecretIDs, len(actualSecretIDs), actualSecretIDs)
				return
			}

			// Validate all expected IDs are present (order-independent)
			if len(actualSecretIDs) > 0 {
				for _, expectedID := range tt.expectedSecretIDs {
					found := false
					for _, actualID := range actualSecretIDs {
						if actualID == expectedID {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected secret ID '%s' not found in result %v", expectedID, actualSecretIDs)
					}
				}
			}

			// Validate that all returned secrets have initialized SecretDetails
			for _, secret := range result {
				if secret.SecretDetails == nil {
					t.Errorf("Secret %s has nil SecretDetails, expected initialized map", secret.SecretID)
				}
			}
		})
	}
}

// createTestService creates a test service with mocked ListSecrets.
// This is simple: we just inject a function that returns our test data.
func createTestService(mockSecrets []*vmsecretsmodels.IdsecSIAVMSecret) *IdsecSIASecretsVMService {
	service := &IdsecSIASecretsVMService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		// Inject mock function to return test data
		mockListSecrets: func() ([]*vmsecretsmodels.IdsecSIAVMSecret, error) {
			return mockSecrets, nil
		},
	}
	return service
}
