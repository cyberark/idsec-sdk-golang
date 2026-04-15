package vmsecrets

import (
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	vmsecretsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsvm/models"
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "PCloudAccount",
					SecretName:    "test-pcloud",
					IsActive:      true,
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-3",
					SecretType:    "ProvisionerUser",
					SecretName:    "another-provisioner",
					IsActive:      true,
					AccountDomain: "local",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "PCloudAccount",
					SecretName:    "test-pcloud",
					IsActive:      true,
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "another-pcloud",
					IsActive:      false,
					AccountDomain: "domain",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-domain-provisioner",
					IsActive:      true,
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-3",
					SecretType:    "ProvisionerUser",
					SecretName:    "other-provisioner",
					IsActive:      true,
					AccountDomain: "local",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-domain-provisioner",
					IsActive:      true,
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-3",
					SecretType:    "ProvisionerUser",
					SecretName:    "other-provisioner",
					IsActive:      true,
					AccountDomain: "local",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "inactive-secret",
					IsActive:      false,
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "active-secret-2",
					IsActive:      true,
					AccountDomain: "local",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "inactive-secret-1",
					IsActive:      false,
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "inactive-secret-2",
					IsActive:      false,
					AccountDomain: "domain",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "domain-secret",
					IsActive:      true,
					AccountDomain: "MYDOMAIN",
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "another-local-secret",
					IsActive:      true,
					AccountDomain: "local",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "domain-secret",
					IsActive:      true,
					AccountDomain: "MYDOMAIN",
				},
				{
					SecretID:      "secret-3",
					SecretType:    "ProvisionerUser",
					SecretName:    "otherdomain-secret",
					IsActive:      true,
					AccountDomain: "OTHERDOMAIN",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-domain-provisioner",
					IsActive:      false,
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-3",
					SecretType:    "PCloudAccount",
					SecretName:    "test-pcloud",
					IsActive:      true,
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-4",
					SecretType:    "ProvisionerUser",
					SecretName:    "test-active-provisioner",
					IsActive:      true,
					AccountDomain: "DOMAIN",
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
					AccountDomain: "local",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "PCloudAccount",
					SecretName:    "test-pcloud",
					IsActive:      false,
					AccountDomain: "domain",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "secret-uppercase",
					IsActive:      true,
					AccountDomain: "LOCAL",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "secret-without-domain",
					IsActive:      true,
					AccountDomain: "",
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
					AccountDomain: "local",
				},
				{
					SecretID:      "secret-2",
					SecretType:    "ProvisionerUser",
					SecretName:    "inactive-secret",
					IsActive:      false,
					AccountDomain: "local",
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
					AccountDomain: "local",
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
					AccountDomain: "local",
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
					AccountDomain: "local",
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
					AccountDomain: "local",
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
			result, err := service.ListBy(tt.filter)

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

// TestValidateEphemeralDomainUserParams tests the validation logic for ephemeral domain user parameters.
func TestValidateEphemeralDomainUserParams(t *testing.T) {
	tests := []struct {
		name           string
		params         vmsecretsmodels.EphemeralDomainUserParams
		expectedError  bool
		expectedErrMsg string
	}{
		{
			name: "valid_params_with_all_defaults",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps: true,
				UseWinrmForHTTPS:         true,
			},
			expectedError: false,
		},
		{
			name: "valid_params_with_certificate_validation_enabled",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "dc.example.com",
				DomainControllerNetbios:                     "DC",
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsCertificate:            "cert-id-123",
				EphemeralDomainUserLocation:                 "OU=Users,DC=example,DC=com",
				UseWinrmForHTTPS:                            true,
				WinrmEnableCertificateValidation:            true,
				WinrmCertificate:                            "winrm-cert-456",
			},
			expectedError: false,
		},
		{
			name: "error_domain_controller_cert_validation_without_ldaps",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                    false,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsCertificate:            "cert-id-123",
				UseWinrmForHTTPS:                            true,
			},
			expectedError:  true,
			expectedErrMsg: "domain-controller-enable-certificate-validation requires domain-controller-use-ldaps to be true",
		},
		{
			name: "error_domain_controller_cert_validation_without_certificate",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsCertificate:            "", // Missing certificate
				UseWinrmForHTTPS:                            true,
			},
			expectedError:  true,
			expectedErrMsg: "domain-controller-enable-certificate-validation requires domain-controller-ldaps-certificate to be provided",
		},
		{
			name: "error_winrm_cert_validation_without_https",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:         true,
				UseWinrmForHTTPS:                 false,
				WinrmEnableCertificateValidation: true,
				WinrmCertificate:                 "winrm-cert-456",
			},
			expectedError:  true,
			expectedErrMsg: "winrm-enable-certificate-validation requires use-winrm-for-https to be true",
		},
		{
			name: "error_winrm_cert_validation_without_certificate",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:         true,
				UseWinrmForHTTPS:                 true,
				WinrmEnableCertificateValidation: true,
				WinrmCertificate:                 "", // Missing certificate
			},
			expectedError:  true,
			expectedErrMsg: "winrm-enable-certificate-validation requires winrm-certificate to be provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := vmsecretsmodels.ValidateEphemeralDomainUserParams(tt.params)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if !strings.Contains(err.Error(), tt.expectedErrMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestExtractEphemeralParamsFromAddSecret tests the extraction of ephemeral params with defaults.
func TestExtractEphemeralParamsFromAddSecret(t *testing.T) {
	tests := []struct {
		name      string
		addSecret *vmsecretsmodels.IdsecSIAVMAddSecret
		expected  vmsecretsmodels.EphemeralDomainUserParams
	}{
		{
			name:      "defaults_applied_when_nil",
			addSecret: &vmsecretsmodels.IdsecSIAVMAddSecret{
				// DomainControllerUseLdaps and UseWinrmForHTTPS are nil (not set)
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "",
				DomainControllerNetbios:                     "",
				EphemeralDomainUserLocation:                 "",
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: false,
				DomainControllerLdapsCertificate:            "",
				UseWinrmForHTTPS:                            true,
				WinrmEnableCertificateValidation:            false,
				WinrmCertificate:                            "",
			},
		},
		{
			name: "explicit_false_overrides_default",
			addSecret: &vmsecretsmodels.IdsecSIAVMAddSecret{
				DomainControllerUseLdaps: boolPtr(false),
				UseWinrmForHTTPS:         boolPtr(false),
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "",
				DomainControllerNetbios:                     "",
				EphemeralDomainUserLocation:                 "",
				DomainControllerUseLdaps:                    false, // explicit false
				DomainControllerEnableCertificateValidation: false,
				DomainControllerLdapsCertificate:            "",
				UseWinrmForHTTPS:                            false, // explicit false
				WinrmEnableCertificateValidation:            false,
				WinrmCertificate:                            "",
			},
		},
		{
			name: "all_fields_populated",
			addSecret: &vmsecretsmodels.IdsecSIAVMAddSecret{
				DomainControllerName:                        "dc.example.com",
				DomainControllerNetbios:                     "DC",
				EphemeralDomainUserLocation:                 "OU=Users,DC=example,DC=com",
				DomainControllerUseLdaps:                    boolPtr(true),
				DomainControllerEnableCertificateValidation: boolPtr(true),
				DomainControllerLdapsCertificate:            "ldaps-cert-123",
				UseWinrmForHTTPS:                            boolPtr(true),
				WinrmEnableCertificateValidation:            boolPtr(true),
				WinrmCertificate:                            "winrm-cert-456",
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "dc.example.com",
				DomainControllerNetbios:                     "DC",
				EphemeralDomainUserLocation:                 "OU=Users,DC=example,DC=com",
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsCertificate:            "ldaps-cert-123",
				UseWinrmForHTTPS:                            true,
				WinrmEnableCertificateValidation:            true,
				WinrmCertificate:                            "winrm-cert-456",
			},
		},
		{
			name: "partial_fields_with_defaults",
			addSecret: &vmsecretsmodels.IdsecSIAVMAddSecret{
				DomainControllerName:             "dc.example.com",
				EphemeralDomainUserLocation:      "OU=Users,DC=example,DC=com",
				DomainControllerLdapsCertificate: "ldaps-cert-123",
				// DomainControllerUseLdaps and UseWinrmForHTTPS are nil - should default to true
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "dc.example.com",
				DomainControllerNetbios:                     "",
				EphemeralDomainUserLocation:                 "OU=Users,DC=example,DC=com",
				DomainControllerUseLdaps:                    true, // default
				DomainControllerEnableCertificateValidation: false,
				DomainControllerLdapsCertificate:            "ldaps-cert-123",
				UseWinrmForHTTPS:                            true, // default
				WinrmEnableCertificateValidation:            false,
				WinrmCertificate:                            "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := vmsecretsmodels.ExtractEphemeralParamsFromAddSecret(tt.addSecret)

			if params.DomainControllerName != tt.expected.DomainControllerName {
				t.Errorf("DomainControllerName: expected %q, got %q", tt.expected.DomainControllerName, params.DomainControllerName)
			}
			if params.DomainControllerNetbios != tt.expected.DomainControllerNetbios {
				t.Errorf("DomainControllerNetbios: expected %q, got %q", tt.expected.DomainControllerNetbios, params.DomainControllerNetbios)
			}
			if params.EphemeralDomainUserLocation != tt.expected.EphemeralDomainUserLocation {
				t.Errorf("EphemeralDomainUserLocation: expected %q, got %q", tt.expected.EphemeralDomainUserLocation, params.EphemeralDomainUserLocation)
			}
			if params.DomainControllerUseLdaps != tt.expected.DomainControllerUseLdaps {
				t.Errorf("DomainControllerUseLdaps: expected %v, got %v", tt.expected.DomainControllerUseLdaps, params.DomainControllerUseLdaps)
			}
			if params.DomainControllerEnableCertificateValidation != tt.expected.DomainControllerEnableCertificateValidation {
				t.Errorf("DomainControllerEnableCertificateValidation: expected %v, got %v", tt.expected.DomainControllerEnableCertificateValidation, params.DomainControllerEnableCertificateValidation)
			}
			if params.DomainControllerLdapsCertificate != tt.expected.DomainControllerLdapsCertificate {
				t.Errorf("DomainControllerLdapsCertificate: expected %q, got %q", tt.expected.DomainControllerLdapsCertificate, params.DomainControllerLdapsCertificate)
			}
			if params.UseWinrmForHTTPS != tt.expected.UseWinrmForHTTPS {
				t.Errorf("UseWinrmForHTTPS: expected %v, got %v", tt.expected.UseWinrmForHTTPS, params.UseWinrmForHTTPS)
			}
			if params.WinrmEnableCertificateValidation != tt.expected.WinrmEnableCertificateValidation {
				t.Errorf("WinrmEnableCertificateValidation: expected %v, got %v", tt.expected.WinrmEnableCertificateValidation, params.WinrmEnableCertificateValidation)
			}
			if params.WinrmCertificate != tt.expected.WinrmCertificate {
				t.Errorf("WinrmCertificate: expected %q, got %q", tt.expected.WinrmCertificate, params.WinrmCertificate)
			}
		})
	}
}

// TestExtractEphemeralParamsFromChangeSecretWithMerge tests the extraction and merging of ephemeral params.
func TestExtractEphemeralParamsFromChangeSecretWithMerge(t *testing.T) {
	tests := []struct {
		name         string
		changeSecret *vmsecretsmodels.IdsecSIAVMChangeSecret
		existingData map[string]interface{}
		expected     vmsecretsmodels.EphemeralDomainUserParams
	}{
		{
			name: "user_value_overrides_existing",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerName: "new-dc.example.com",
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_name":                          "old-dc.example.com",
					"domain_controller_netbios":                       "OLDDC",
					"domain_controller_use_ldaps":                     false,
					"domain_controller_enable_certificate_validation": true,
					"domain_controller_ldaps_certificate":             "old-cert",
				},
				"ephemeral_domain_user_location": "OU=Old,DC=example,DC=com",
				"winrm_info": map[string]interface{}{
					"use_winrm_for_https":                 false,
					"winrm_enable_certificate_validation": true,
					"winrm_certificate":                   "old-winrm-cert",
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "new-dc.example.com", // user override
				DomainControllerNetbios:                     "OLDDC",              // preserved
				EphemeralDomainUserLocation:                 "OU=Old,DC=example,DC=com",
				DomainControllerUseLdaps:                    false, // preserved
				DomainControllerEnableCertificateValidation: true,  // preserved
				DomainControllerLdapsCertificate:            "old-cert",
				UseWinrmForHTTPS:                            false, // preserved
				WinrmEnableCertificateValidation:            true,  // preserved
				WinrmCertificate:                            "old-winrm-cert",
			},
		},
		{
			name:         "existing_values_preserved_when_not_provided",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_name":                          "existing-dc.example.com",
					"domain_controller_netbios":                       "EXISTINGDC",
					"domain_controller_use_ldaps":                     false,
					"domain_controller_enable_certificate_validation": true,
					"domain_controller_ldaps_certificate":             "existing-cert",
				},
				"ephemeral_domain_user_location": "OU=Existing,DC=example,DC=com",
				"winrm_info": map[string]interface{}{
					"use_winrm_for_https":                 false,
					"winrm_enable_certificate_validation": true,
					"winrm_certificate":                   "existing-winrm-cert",
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "existing-dc.example.com",
				DomainControllerNetbios:                     "EXISTINGDC",
				EphemeralDomainUserLocation:                 "OU=Existing,DC=example,DC=com",
				DomainControllerUseLdaps:                    false,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsCertificate:            "existing-cert",
				UseWinrmForHTTPS:                            false,
				WinrmEnableCertificateValidation:            true,
				WinrmCertificate:                            "existing-winrm-cert",
			},
		},
		{
			name: "defaults_applied_when_no_existing_data",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerName: "new-dc.example.com",
			},
			existingData: nil,
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "new-dc.example.com",
				DomainControllerNetbios:                     "",
				EphemeralDomainUserLocation:                 "",
				DomainControllerUseLdaps:                    true, // default
				DomainControllerEnableCertificateValidation: false,
				DomainControllerLdapsCertificate:            "",
				UseWinrmForHTTPS:                            true, // default
				WinrmEnableCertificateValidation:            false,
				WinrmCertificate:                            "",
			},
		},
		{
			name: "explicit_false_pointer_overrides_existing_true",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerUseLdaps: boolPtr(false),
				UseWinrmForHTTPS:         boolPtr(false),
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_use_ldaps": true,
				},
				"winrm_info": map[string]interface{}{
					"use_winrm_for_https": true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "",
				DomainControllerNetbios:                     "",
				EphemeralDomainUserLocation:                 "",
				DomainControllerUseLdaps:                    false, // user explicit false
				DomainControllerEnableCertificateValidation: false,
				DomainControllerLdapsCertificate:            "",
				UseWinrmForHTTPS:                            false, // user explicit false
				WinrmEnableCertificateValidation:            false,
				WinrmCertificate:                            "",
			},
		},
		{
			name: "all_user_values_override_existing",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerName:                        "new-dc.example.com",
				DomainControllerNetbios:                     "NEWDC",
				EphemeralDomainUserLocation:                 "OU=New,DC=example,DC=com",
				DomainControllerUseLdaps:                    boolPtr(true),
				DomainControllerEnableCertificateValidation: boolPtr(true),
				DomainControllerLdapsCertificate:            "new-cert",
				UseWinrmForHTTPS:                            boolPtr(true),
				WinrmEnableCertificateValidation:            boolPtr(true),
				WinrmCertificate:                            "new-winrm-cert",
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_name":                          "old-dc.example.com",
					"domain_controller_netbios":                       "OLDDC",
					"domain_controller_use_ldaps":                     false,
					"domain_controller_enable_certificate_validation": false,
					"domain_controller_ldaps_certificate":             "old-cert",
				},
				"ephemeral_domain_user_location": "OU=Old,DC=example,DC=com",
				"winrm_info": map[string]interface{}{
					"use_winrm_for_https":                 false,
					"winrm_enable_certificate_validation": false,
					"winrm_certificate":                   "old-winrm-cert",
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "new-dc.example.com",
				DomainControllerNetbios:                     "NEWDC",
				EphemeralDomainUserLocation:                 "OU=New,DC=example,DC=com",
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsCertificate:            "new-cert",
				UseWinrmForHTTPS:                            true,
				WinrmEnableCertificateValidation:            true,
				WinrmCertificate:                            "new-winrm-cert",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := vmsecretsmodels.ExtractEphemeralParamsFromChangeSecret(tt.changeSecret, tt.existingData)

			if params.DomainControllerName != tt.expected.DomainControllerName {
				t.Errorf("DomainControllerName: expected %q, got %q", tt.expected.DomainControllerName, params.DomainControllerName)
			}
			if params.DomainControllerNetbios != tt.expected.DomainControllerNetbios {
				t.Errorf("DomainControllerNetbios: expected %q, got %q", tt.expected.DomainControllerNetbios, params.DomainControllerNetbios)
			}
			if params.EphemeralDomainUserLocation != tt.expected.EphemeralDomainUserLocation {
				t.Errorf("EphemeralDomainUserLocation: expected %q, got %q", tt.expected.EphemeralDomainUserLocation, params.EphemeralDomainUserLocation)
			}
			if params.DomainControllerUseLdaps != tt.expected.DomainControllerUseLdaps {
				t.Errorf("DomainControllerUseLdaps: expected %v, got %v", tt.expected.DomainControllerUseLdaps, params.DomainControllerUseLdaps)
			}
			if params.DomainControllerEnableCertificateValidation != tt.expected.DomainControllerEnableCertificateValidation {
				t.Errorf("DomainControllerEnableCertificateValidation: expected %v, got %v", tt.expected.DomainControllerEnableCertificateValidation, params.DomainControllerEnableCertificateValidation)
			}
			if params.DomainControllerLdapsCertificate != tt.expected.DomainControllerLdapsCertificate {
				t.Errorf("DomainControllerLdapsCertificate: expected %q, got %q", tt.expected.DomainControllerLdapsCertificate, params.DomainControllerLdapsCertificate)
			}
			if params.UseWinrmForHTTPS != tt.expected.UseWinrmForHTTPS {
				t.Errorf("UseWinrmForHTTPS: expected %v, got %v", tt.expected.UseWinrmForHTTPS, params.UseWinrmForHTTPS)
			}
			if params.WinrmEnableCertificateValidation != tt.expected.WinrmEnableCertificateValidation {
				t.Errorf("WinrmEnableCertificateValidation: expected %v, got %v", tt.expected.WinrmEnableCertificateValidation, params.WinrmEnableCertificateValidation)
			}
			if params.WinrmCertificate != tt.expected.WinrmCertificate {
				t.Errorf("WinrmCertificate: expected %q, got %q", tt.expected.WinrmCertificate, params.WinrmCertificate)
			}
		})
	}
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}
