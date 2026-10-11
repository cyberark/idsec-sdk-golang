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
			expectedErrMsg: "domain-controller-enable-certificate-validation requires domain-controller-ldaps-certificate or domain-controller-ldaps-load-all-certificates to be provided",
		},
		{
			name: "valid_certificate_validation_with_load_all_certificates",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsLoadAllCertificates:    true,
				UseWinrmForHTTPS:                            true,
				WinrmEnableCertificateValidation:            true,
				WinrmLoadAllCertificates:                    true,
			},
			expectedError: false,
		},
		{
			name: "valid_certificate_and_load_all_certificates_without_certificate_validation",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                 true,
				DomainControllerLdapsCertificate:         "cert-id-123",
				DomainControllerLdapsLoadAllCertificates: true,
				UseWinrmForHTTPS:                         true,
				WinrmCertificate:                         "winrm-cert-456",
				WinrmLoadAllCertificates:                 true,
			},
			expectedError: false,
		},
		{
			name: "error_domain_controller_certificate_with_load_all_certificates",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsCertificate:            "cert-id-123",
				DomainControllerLdapsLoadAllCertificates:    true,
				UseWinrmForHTTPS:                            true,
			},
			expectedError:  true,
			expectedErrMsg: "domain-controller-ldaps-certificate and domain-controller-ldaps-load-all-certificates cannot be used together",
		},
		{
			name: "error_winrm_certificate_with_load_all_certificates",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:         true,
				UseWinrmForHTTPS:                 true,
				WinrmEnableCertificateValidation: true,
				WinrmCertificate:                 "winrm-cert-456",
				WinrmLoadAllCertificates:         true,
			},
			expectedError:  true,
			expectedErrMsg: "winrm-certificate and winrm-load-all-certificates cannot be used together",
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
			expectedErrMsg: "winrm-enable-certificate-validation requires winrm-certificate or winrm-load-all-certificates to be provided",
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
				DomainControllerAutomaticDiscovery:          false, // nil defaults to false, not true
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
			name: "automatic_discovery_explicitly_true",
			addSecret: &vmsecretsmodels.IdsecSIAVMAddSecret{
				DomainControllerAutomaticDiscovery: boolPtr(true),
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerAutomaticDiscovery: true,
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
		},
		{
			name: "automatic_discovery_explicitly_false",
			addSecret: &vmsecretsmodels.IdsecSIAVMAddSecret{
				DomainControllerAutomaticDiscovery: boolPtr(false),
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerAutomaticDiscovery: false,
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
		},
		{
			name: "load_all_certificates_explicitly_true",
			addSecret: &vmsecretsmodels.IdsecSIAVMAddSecret{
				DomainControllerLdapsLoadAllCertificates: boolPtr(true),
				WinrmLoadAllCertificates:                 boolPtr(true),
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                 true,
				DomainControllerLdapsLoadAllCertificates: true,
				UseWinrmForHTTPS:                         true,
				WinrmLoadAllCertificates:                 true,
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
			if params.DomainControllerAutomaticDiscovery != tt.expected.DomainControllerAutomaticDiscovery {
				t.Errorf("DomainControllerAutomaticDiscovery: expected %v, got %v", tt.expected.DomainControllerAutomaticDiscovery, params.DomainControllerAutomaticDiscovery)
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
			if params.DomainControllerLdapsLoadAllCertificates != tt.expected.DomainControllerLdapsLoadAllCertificates {
				t.Errorf("DomainControllerLdapsLoadAllCertificates: expected %v, got %v", tt.expected.DomainControllerLdapsLoadAllCertificates, params.DomainControllerLdapsLoadAllCertificates)
			}
			if params.WinrmLoadAllCertificates != tt.expected.WinrmLoadAllCertificates {
				t.Errorf("WinrmLoadAllCertificates: expected %v, got %v", tt.expected.WinrmLoadAllCertificates, params.WinrmLoadAllCertificates)
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
		{
			// A secret stored before automatic discovery existed has no such key
			name:         "automatic_discovery_defaults_to_false_when_absent_from_existing",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_name":      "existing-dc.example.com",
					"domain_controller_use_ldaps": true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:               "existing-dc.example.com",
				DomainControllerAutomaticDiscovery: false,
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
		},
		{
			name:         "automatic_discovery_preserved_from_existing",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_automatic_discovery": true,
					"domain_controller_use_ldaps":           true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerAutomaticDiscovery: true,
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
		},
		{
			name: "automatic_discovery_explicit_false_overrides_existing_true",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerAutomaticDiscovery: boolPtr(false),
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_automatic_discovery": true,
					"domain_controller_use_ldaps":           true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerAutomaticDiscovery: false, // user explicit false
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
		},
		{
			name: "automatic_discovery_disabled_still_inherits_domain_controller_name",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerAutomaticDiscovery: boolPtr(false),
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_name":      "existing-dc.example.com",
					"domain_controller_netbios":   "EXISTINGDC",
					"domain_controller_use_ldaps": true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:               "existing-dc.example.com",
				DomainControllerNetbios:            "EXISTINGDC",
				DomainControllerAutomaticDiscovery: false,
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
		},
		{
			name:         "load_all_certificates_preserved_on_unrelated_change",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{SecretName: "renamed"},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_enable_certificate_validation": true,
					"domain_controller_ldaps_load_all_certificates":   true,
				},
				"winrm_info": map[string]interface{}{
					"winrm_enable_certificate_validation": true,
					"winrm_load_all_certificates":         true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsLoadAllCertificates:    true,
				UseWinrmForHTTPS:                            true,
				WinrmEnableCertificateValidation:            true,
				WinrmLoadAllCertificates:                    true,
			},
		},
		{
			name: "load_all_disabled_still_inherits_certificate",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerLdapsLoadAllCertificates: boolPtr(false),
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_ldaps_certificate": "existing-cert",
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:         true,
				DomainControllerLdapsCertificate: "existing-cert",
				UseWinrmForHTTPS:                 true,
			},
		},
		{
			name: "automatic_discovery_enabled_clears_inherited_domain_controller_name",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerAutomaticDiscovery: boolPtr(true),
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_name":              "old-dc.example.com",
					"domain_controller_netbios":           "OLDDC",
					"domain_controller_ldaps_certificate": "old-cert",
					"domain_controller_use_ldaps":         true,
				},
				"ephemeral_domain_user_location": "OU=Old,DC=example,DC=com",
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:                        "", // superseded
				DomainControllerNetbios:                     "", // superseded
				DomainControllerAutomaticDiscovery:          true,
				EphemeralDomainUserLocation:                 "OU=Old,DC=example,DC=com", // untouched
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: false,
				DomainControllerLdapsCertificate:            "old-cert", // untouched
				UseWinrmForHTTPS:                            true,
			},
		},
		{
			name: "explicit_domain_controller_name_clears_inherited_automatic_discovery",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerName: "new-dc.example.com",
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_automatic_discovery": true,
					"domain_controller_use_ldaps":           true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:               "new-dc.example.com",
				DomainControllerAutomaticDiscovery: false, // superseded
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
		},
		{
			name: "explicit_domain_controller_netbios_clears_inherited_automatic_discovery",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerNetbios: "NEWDC",
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_automatic_discovery": true,
					"domain_controller_use_ldaps":           true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerNetbios:            "NEWDC",
				DomainControllerAutomaticDiscovery: false, // superseded
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
		},
		{
			// Both given at once are sent as-is for the service to reject
			name: "explicit_conflict_preserved_for_validation",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerName:               "dc.example.com",
				DomainControllerAutomaticDiscovery: boolPtr(true),
			},
			existingData: nil,
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:               "dc.example.com",
				DomainControllerAutomaticDiscovery: true,
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
		},
		{
			name: "load_all_certificates_enabled_clears_inherited_certificates",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerLdapsLoadAllCertificates: boolPtr(true),
				WinrmLoadAllCertificates:                 boolPtr(true),
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_enable_certificate_validation": true,
					"domain_controller_ldaps_certificate":             "old-cert",
				},
				"winrm_info": map[string]interface{}{
					"winrm_enable_certificate_validation": true,
					"winrm_certificate":                   "old-winrm-cert",
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                    true,
				DomainControllerEnableCertificateValidation: true,
				DomainControllerLdapsCertificate:            "", // superseded
				DomainControllerLdapsLoadAllCertificates:    true,
				UseWinrmForHTTPS:                            true,
				WinrmEnableCertificateValidation:            true,
				WinrmCertificate:                            "", // superseded
				WinrmLoadAllCertificates:                    true,
			},
		},
		{
			name: "explicit_certificates_clear_inherited_load_all",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerLdapsCertificate: "new-cert",
				WinrmCertificate:                 "new-winrm-cert",
			},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_ldaps_load_all_certificates": true,
				},
				"winrm_info": map[string]interface{}{
					"winrm_load_all_certificates": true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                 true,
				DomainControllerLdapsCertificate:         "new-cert",
				DomainControllerLdapsLoadAllCertificates: false, // superseded
				UseWinrmForHTTPS:                         true,
				WinrmCertificate:                         "new-winrm-cert",
				WinrmLoadAllCertificates:                 false, // superseded
			},
		},
		{
			name: "explicit_certificate_and_load_all_preserved_for_validation",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{
				DomainControllerLdapsCertificate:         "new-cert",
				DomainControllerLdapsLoadAllCertificates: boolPtr(true),
				WinrmCertificate:                         "new-winrm-cert",
				WinrmLoadAllCertificates:                 boolPtr(true),
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                 true,
				DomainControllerLdapsCertificate:         "new-cert",
				DomainControllerLdapsLoadAllCertificates: true,
				UseWinrmForHTTPS:                         true,
				WinrmCertificate:                         "new-winrm-cert",
				WinrmLoadAllCertificates:                 true,
			},
		},
		{
			// Inherited load-all takes precedence over an inherited certificate, as in jit-ui
			name:         "inherited_load_all_wins_over_inherited_certificate",
			changeSecret: &vmsecretsmodels.IdsecSIAVMChangeSecret{},
			existingData: map[string]interface{}{
				"domain_controller": map[string]interface{}{
					"domain_controller_ldaps_certificate":           "old-cert",
					"domain_controller_ldaps_load_all_certificates": true,
				},
				"winrm_info": map[string]interface{}{
					"winrm_certificate":           "old-winrm-cert",
					"winrm_load_all_certificates": true,
				},
			},
			expected: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerUseLdaps:                 true,
				DomainControllerLdapsCertificate:         "",
				DomainControllerLdapsLoadAllCertificates: true,
				UseWinrmForHTTPS:                         true,
				WinrmCertificate:                         "",
				WinrmLoadAllCertificates:                 true,
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
			if params.DomainControllerAutomaticDiscovery != tt.expected.DomainControllerAutomaticDiscovery {
				t.Errorf("DomainControllerAutomaticDiscovery: expected %v, got %v", tt.expected.DomainControllerAutomaticDiscovery, params.DomainControllerAutomaticDiscovery)
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
			if params.DomainControllerLdapsLoadAllCertificates != tt.expected.DomainControllerLdapsLoadAllCertificates {
				t.Errorf("DomainControllerLdapsLoadAllCertificates: expected %v, got %v", tt.expected.DomainControllerLdapsLoadAllCertificates, params.DomainControllerLdapsLoadAllCertificates)
			}
			if params.WinrmLoadAllCertificates != tt.expected.WinrmLoadAllCertificates {
				t.Errorf("WinrmLoadAllCertificates: expected %v, got %v", tt.expected.WinrmLoadAllCertificates, params.WinrmLoadAllCertificates)
			}
		})
	}
}

// TestBuildEphemeralDomainUserDataMap tests that every domain controller key is emitted, including false ones.
func TestBuildEphemeralDomainUserDataMap(t *testing.T) {
	tests := []struct {
		name                      string
		params                    vmsecretsmodels.EphemeralDomainUserParams
		expectedAutomaticDiscover bool
	}{
		{
			name: "automatic_discovery_true_is_emitted",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerAutomaticDiscovery: true,
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
			expectedAutomaticDiscover: true,
		},
		{
			name: "automatic_discovery_false_is_still_emitted",
			params: vmsecretsmodels.EphemeralDomainUserParams{
				DomainControllerName:               "dc.example.com",
				DomainControllerAutomaticDiscovery: false,
				DomainControllerUseLdaps:           true,
				UseWinrmForHTTPS:                   true,
			},
			expectedAutomaticDiscover: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := vmsecretsmodels.BuildEphemeralDomainUserDataMap(tt.params)

			dcMap, ok := data["domain_controller"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected domain_controller to be a map, got %T", data["domain_controller"])
			}
			if len(dcMap) != 7 {
				t.Errorf("expected 7 domain_controller keys, got %d: %v", len(dcMap), dcMap)
			}
			if loadAll, ok := dcMap["domain_controller_ldaps_load_all_certificates"].(bool); !ok || loadAll {
				t.Errorf("expected domain_controller_ldaps_load_all_certificates to be emitted as false, got %v", dcMap["domain_controller_ldaps_load_all_certificates"])
			}
			winrmMap, ok := data["winrm_info"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected winrm_info to be a map, got %T", data["winrm_info"])
			}
			if loadAll, ok := winrmMap["winrm_load_all_certificates"].(bool); !ok || loadAll {
				t.Errorf("expected winrm_load_all_certificates to be emitted as false, got %v", winrmMap["winrm_load_all_certificates"])
			}
			value, ok := dcMap["domain_controller_automatic_discovery"]
			if !ok {
				t.Fatal("expected domain_controller_automatic_discovery key to be present")
			}
			automaticDiscovery, ok := value.(bool)
			if !ok {
				t.Fatalf("expected domain_controller_automatic_discovery to be a bool, got %T", value)
			}
			if automaticDiscovery != tt.expectedAutomaticDiscover {
				t.Errorf("domain_controller_automatic_discovery: expected %v, got %v", tt.expectedAutomaticDiscover, automaticDiscovery)
			}
		})
	}
}

// TestChangeSecretDisablesAutomaticDiscovery tests that an explicit false overrides a stored true through merge and build.
func TestChangeSecretDisablesAutomaticDiscovery(t *testing.T) {
	existingData := map[string]interface{}{
		"domain_controller": map[string]interface{}{
			"domain_controller_automatic_discovery": true,
			"domain_controller_use_ldaps":           true,
		},
		"ephemeral_domain_user_location": "OU=Test,DC=example,DC=com",
	}
	changeSecret := &vmsecretsmodels.IdsecSIAVMChangeSecret{
		DomainControllerAutomaticDiscovery: boolPtr(false),
	}

	params := vmsecretsmodels.ExtractEphemeralParamsFromChangeSecret(changeSecret, existingData)
	if params.DomainControllerAutomaticDiscovery {
		t.Fatal("expected explicit false to override the stored true")
	}

	data := vmsecretsmodels.BuildEphemeralDomainUserDataMap(params)
	dcMap, ok := data["domain_controller"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected domain_controller to be a map, got %T", data["domain_controller"])
	}
	value, ok := dcMap["domain_controller_automatic_discovery"]
	if !ok {
		t.Fatal("expected domain_controller_automatic_discovery key to be present so the stored true is overwritten")
	}
	if automaticDiscovery, _ := value.(bool); automaticDiscovery {
		t.Error("expected the stored state to be rewritten with false")
	}
	if location := data["ephemeral_domain_user_location"]; location != "OU=Test,DC=example,DC=com" {
		t.Errorf("expected the unrelated location to be preserved, got %v", location)
	}
}

// TestPopulateFromSecretDetailsJSONAutomaticDiscovery tests reading automatic discovery back from secret_details.
func TestPopulateFromSecretDetailsJSONAutomaticDiscovery(t *testing.T) {
	// The method never dereferences the receiver, so a service without HTTP mocking is sufficient
	service := createTestService(nil)

	tests := []struct {
		name          string
		secretDetails string
		expected      *bool
	}{
		{
			name:          "automatic_discovery_true",
			secretDetails: `{"account_domain":"example.com","ephemeral_domain_user_data":{"domain_controller":{"domain_controller_automatic_discovery":true}}}`,
			expected:      boolPtr(true),
		},
		{
			name:          "automatic_discovery_false",
			secretDetails: `{"account_domain":"example.com","ephemeral_domain_user_data":{"domain_controller":{"domain_controller_automatic_discovery":false}}}`,
			expected:      boolPtr(false),
		},
		{
			// nil means not provided, not an explicit false
			name:          "automatic_discovery_absent",
			secretDetails: `{"account_domain":"example.com","ephemeral_domain_user_data":{"domain_controller":{"domain_controller_name":"dc.example.com"}}}`,
			expected:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &vmsecretsmodels.IdsecSIAVMSecret{}
			if err := service.populateFromSecretDetailsJSON(tt.secretDetails, secret); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			switch {
			case tt.expected == nil:
				if secret.DomainControllerAutomaticDiscovery != nil {
					t.Errorf("expected DomainControllerAutomaticDiscovery to stay nil, got %v", *secret.DomainControllerAutomaticDiscovery)
				}
			case secret.DomainControllerAutomaticDiscovery == nil:
				t.Errorf("expected DomainControllerAutomaticDiscovery to be %v, got nil", *tt.expected)
			case *secret.DomainControllerAutomaticDiscovery != *tt.expected:
				t.Errorf("DomainControllerAutomaticDiscovery: expected %v, got %v", *tt.expected, *secret.DomainControllerAutomaticDiscovery)
			}
		})
	}

	// Round trip through the map ChangeSecret merges against
	t.Run("round_trip_into_existing_ephemeral_data", func(t *testing.T) {
		secret := &vmsecretsmodels.IdsecSIAVMSecret{}
		secretDetails := `{"account_domain":"example.com","ephemeral_domain_user_data":{"domain_controller":{"domain_controller_automatic_discovery":true,"domain_controller_use_ldaps":true}}}`
		if err := service.populateFromSecretDetailsJSON(secretDetails, secret); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		existingData := vmsecretsmodels.EphemeralDomainUserDataMapFromSecret(secret)
		dcMap, ok := existingData["domain_controller"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected domain_controller to be a map, got %T", existingData["domain_controller"])
		}
		if automaticDiscovery, _ := dcMap["domain_controller_automatic_discovery"].(bool); !automaticDiscovery {
			t.Error("expected the stored automatic discovery flag to survive the round trip")
		}

		// An unrelated change must not turn it off
		params := vmsecretsmodels.ExtractEphemeralParamsFromChangeSecret(
			&vmsecretsmodels.IdsecSIAVMChangeSecret{SecretName: "renamed"}, existingData)
		if !params.DomainControllerAutomaticDiscovery {
			t.Error("expected an unrelated change to preserve automatic discovery")
		}
	})
}

// TestPopulateFromSecretDetailsJSONLoadAllCertificates tests reading the load-all certificate flags back from secret_details.
func TestPopulateFromSecretDetailsJSONLoadAllCertificates(t *testing.T) {
	service := createTestService(nil)

	tests := []struct {
		name          string
		secretDetails string
		expectedLdaps *bool
		expectedWinrm *bool
	}{
		{
			name:          "both_true",
			secretDetails: `{"account_domain":"example.com","ephemeral_domain_user_data":{"domain_controller":{"domain_controller_ldaps_load_all_certificates":true},"winrm_info":{"winrm_load_all_certificates":true}}}`,
			expectedLdaps: boolPtr(true),
			expectedWinrm: boolPtr(true),
		},
		{
			name:          "both_false",
			secretDetails: `{"account_domain":"example.com","ephemeral_domain_user_data":{"domain_controller":{"domain_controller_ldaps_load_all_certificates":false},"winrm_info":{"winrm_load_all_certificates":false}}}`,
			expectedLdaps: boolPtr(false),
			expectedWinrm: boolPtr(false),
		},
		{
			name:          "absent",
			secretDetails: `{"account_domain":"example.com","ephemeral_domain_user_data":{"domain_controller":{"domain_controller_name":"dc.example.com"},"winrm_info":{"use_winrm_for_https":true}}}`,
		},
	}

	check := func(t *testing.T, field string, got, expected *bool) {
		switch {
		case expected == nil && got != nil:
			t.Errorf("expected %s to stay nil, got %v", field, *got)
		case expected != nil && got == nil:
			t.Errorf("expected %s to be %v, got nil", field, *expected)
		case expected != nil && *got != *expected:
			t.Errorf("%s: expected %v, got %v", field, *expected, *got)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &vmsecretsmodels.IdsecSIAVMSecret{}
			if err := service.populateFromSecretDetailsJSON(tt.secretDetails, secret); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			check(t, "DomainControllerLdapsLoadAllCertificates", secret.DomainControllerLdapsLoadAllCertificates, tt.expectedLdaps)
			check(t, "WinrmLoadAllCertificates", secret.WinrmLoadAllCertificates, tt.expectedWinrm)
		})
	}
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}
