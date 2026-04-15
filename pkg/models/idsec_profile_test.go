package models

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

func TestIdsecProfile_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name            string
		jsonData        string
		expectedError   bool
		expectedProfile *IdsecProfile
		validateFunc    func(t *testing.T, profile *IdsecProfile)
	}{
		{
			name: "success_complete_profile_with_identity_auth",
			jsonData: `{
				"profile_name": "test-profile",
				"profile_description": "Test profile description",
				"auth_profiles": {
					"default": {
						"username": "test@example.com",
						"auth_method": "identity",
						"auth_method_settings": {
							"identity_mfa_method": "pf",
							"identity_mfa_interactive": true,
							"identity_application": "test-app",
							"identity_url": "https://identity.example.com",
							"identity_tenant_subdomain": "test-tenant"
						}
					}
				}
			}`,
			expectedError: false,
			expectedProfile: &IdsecProfile{
				ProfileName:        "test-profile",
				ProfileDescription: "Test profile description",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"default": {
						Username:   "test@example.com",
						AuthMethod: auth.Identity,
						AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{
							IdentityMFAMethod:       "pf",
							IdentityMFAInteractive:  true,
							IdentityURL:             "https://identity.example.com",
							IdentityTenantSubdomain: "test-tenant",
						},
					},
				},
			},
		},
		{
			name: "success_multiple_auth_profiles",
			jsonData: `{
				"profile_name": "multi-profile",
				"profile_description": "Profile with multiple auth methods",
				"auth_profiles": {
					"identity": {
						"username": "user1@example.com",
						"auth_method": "identity",
						"auth_method_settings": {
							"identity_mfa_method": "sms",
							"identity_mfa_interactive": false,
							"identity_application": "app1",
							"identity_url": "https://id1.example.com",
							"identity_tenant_subdomain": "tenant1"
						}
					},
					"direct": {
						"username": "user2@example.com",
						"auth_method": "direct",
						"auth_method_settings": {
							"direct_url": "https://direct.example.com"
						}
					}
				}
			}`,
			expectedError: false,
			validateFunc: func(t *testing.T, profile *IdsecProfile) {
				if profile.ProfileName != "multi-profile" {
					t.Errorf("Expected ProfileName 'multi-profile', got '%s'", profile.ProfileName)
				}
				if len(profile.AuthProfiles) != 2 {
					t.Errorf("Expected 2 auth profiles, got %d", len(profile.AuthProfiles))
				}
				if profile.AuthProfiles["identity"].AuthMethod != auth.Identity {
					t.Errorf("Expected identity auth method, got %s", profile.AuthProfiles["identity"].AuthMethod)
				}
				if profile.AuthProfiles["direct"].AuthMethod != auth.Direct {
					t.Errorf("Expected direct auth method, got %s", profile.AuthProfiles["direct"].AuthMethod)
				}
			},
		},
		{
			name: "success_empty_auth_profiles",
			jsonData: `{
				"profile_name": "empty-profile",
				"profile_description": "Profile with no auth profiles",
				"auth_profiles": {}
			}`,
			expectedError: false,
			expectedProfile: &IdsecProfile{
				ProfileName:        "empty-profile",
				ProfileDescription: "Profile with no auth profiles",
				AuthProfiles:       map[string]*auth.IdsecAuthProfile{},
			},
		},
		{
			name: "success_minimal_profile",
			jsonData: `{
				"profile_name": "minimal",
				"profile_description": "Minimal profile",
				"auth_profiles": {
					"simple": {
						"username": "simple@example.com",
						"auth_method": "default",
						"auth_method_settings": {}
					}
				}
			}`,
			expectedError: false,
			validateFunc: func(t *testing.T, profile *IdsecProfile) {
				if profile.ProfileName != "minimal" {
					t.Errorf("Expected ProfileName 'minimal', got '%s'", profile.ProfileName)
				}
				if profile.AuthProfiles["simple"].Username != "simple@example.com" {
					t.Errorf("Expected username 'simple@example.com', got '%s'", profile.AuthProfiles["simple"].Username)
				}
				if profile.AuthProfiles["simple"].AuthMethod != auth.Default {
					t.Errorf("Expected default auth method, got %s", profile.AuthProfiles["simple"].AuthMethod)
				}
			},
		},
		{
			name:          "error_invalid_json",
			jsonData:      `{"profile_name": "test", "invalid_json"`,
			expectedError: true,
		},
		{
			name: "error_missing_required_fields",
			jsonData: `{
				"auth_profiles": {}
			}`,
			expectedError: false, // JSON unmarshaling succeeds, but fields will be empty
			expectedProfile: &IdsecProfile{
				ProfileName:        "",
				ProfileDescription: "",
				AuthProfiles:       map[string]*auth.IdsecAuthProfile{},
			},
		},
		{
			name: "error_invalid_auth_method",
			jsonData: `{
				"profile_name": "invalid-auth",
				"profile_description": "Profile with invalid auth method",
				"auth_profiles": {
					"invalid": {
						"username": "user@example.com",
						"auth_method": "invalid_method",
						"auth_method_settings": {}
					}
				}
			}`,
			expectedError: true, // This should fail in auth profile unmarshaling
		},
		{
			name: "error_malformed_auth_profile",
			jsonData: `{
				"profile_name": "malformed",
				"profile_description": "Profile with malformed auth profile",
				"auth_profiles": {
					"bad": "not_an_object"
				}
			}`,
			expectedError: true,
		},
		{
			name: "edge_case_null_auth_profiles",
			jsonData: `{
				"profile_name": "null-auth",
				"profile_description": "Profile with null auth profiles",
				"auth_profiles": null
			}`,
			expectedError: false,
			expectedProfile: &IdsecProfile{
				ProfileName:        "null-auth",
				ProfileDescription: "Profile with null auth profiles",
				AuthProfiles:       map[string]*auth.IdsecAuthProfile{},
			},
		},
		{
			name: "edge_case_special_characters_in_names",
			jsonData: `{
				"profile_name": "special-chars_123!@#",
				"profile_description": "Profile with special characters: üñîçödé & symbols",
				"auth_profiles": {
					"key-with_special.chars": {
						"username": "user+test@example.com",
						"auth_method": "default",
						"auth_method_settings": {}
					}
				}
			}`,
			expectedError: false,
			validateFunc: func(t *testing.T, profile *IdsecProfile) {
				if profile.ProfileName != "special-chars_123!@#" {
					t.Errorf("Expected special character profile name, got '%s'", profile.ProfileName)
				}
				if _, exists := profile.AuthProfiles["key-with_special.chars"]; !exists {
					t.Error("Expected auth profile with special characters in key")
				}
			},
		},
		{
			name: "error_invalid_auth_profile_json_structure",
			jsonData: `{
				"profile_name": "invalid-structure",
				"profile_description": "Profile with invalid auth profile JSON structure",
				"auth_profiles": {
					"malformed": {
						"username": "user@example.com",
						"auth_method": "identity",
						"auth_method_settings": {
							"identity_mfa_method": "invalid_json_value",
							"identity_mfa_interactive": "not_a_boolean"
						}
					}
				}
			}`,
			expectedError: true, // This specifically tests line 77: json.Unmarshal(rawMessage, &authProfile)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var profile IdsecProfile
			err := json.Unmarshal([]byte(tt.jsonData), &profile)

			// Validate error expectation
			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return // Don't check result if we expected an error
			}

			// Validate no error when success expected
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Use custom validation if provided
			if tt.validateFunc != nil {
				tt.validateFunc(t, &profile)
				return
			}

			// Validate expected profile if provided
			if tt.expectedProfile != nil {
				if profile.ProfileName != tt.expectedProfile.ProfileName {
					t.Errorf("Expected ProfileName '%s', got '%s'", tt.expectedProfile.ProfileName, profile.ProfileName)
				}
				if profile.ProfileDescription != tt.expectedProfile.ProfileDescription {
					t.Errorf("Expected ProfileDescription '%s', got '%s'", tt.expectedProfile.ProfileDescription, profile.ProfileDescription)
				}

				// Check auth profiles map
				if len(profile.AuthProfiles) != len(tt.expectedProfile.AuthProfiles) {
					t.Errorf("Expected %d auth profiles, got %d", len(tt.expectedProfile.AuthProfiles), len(profile.AuthProfiles))
				}

				for key, expectedAuth := range tt.expectedProfile.AuthProfiles {
					actualAuth, exists := profile.AuthProfiles[key]
					if !exists {
						t.Errorf("Expected auth profile with key '%s' not found", key)
						continue
					}

					if actualAuth.Username != expectedAuth.Username {
						t.Errorf("Expected username '%s', got '%s'", expectedAuth.Username, actualAuth.Username)
					}
					if actualAuth.AuthMethod != expectedAuth.AuthMethod {
						t.Errorf("Expected auth method '%s', got '%s'", expectedAuth.AuthMethod, actualAuth.AuthMethod)
					}

					// Note: AuthMethodSettings comparison is complex due to interface types
					// We rely on the auth package's own unmarshaling tests for detailed validation
					if actualAuth.AuthMethodSettings == nil && expectedAuth.AuthMethodSettings != nil {
						t.Error("Expected auth method settings, got nil")
					}
					if actualAuth.AuthMethodSettings != nil && expectedAuth.AuthMethodSettings == nil {
						t.Error("Expected nil auth method settings, got non-nil")
					}
				}
			}
		})
	}
}

// TestIdsecProfile_UnmarshalJSON_Integration tests the integration with auth package
func TestIdsecProfile_UnmarshalJSON_Integration(t *testing.T) {
	tests := []struct {
		name          string
		jsonData      string
		expectedError bool
		validateAuth  func(t *testing.T, authProfile *auth.IdsecAuthProfile)
	}{
		{
			name: "integration_identity_service_user_auth",
			jsonData: `{
				"profile_name": "integration-test",
				"profile_description": "Integration test profile",
				"auth_profiles": {
					"service": {
						"username": "service@example.com",
						"auth_method": "identity_service_user",
						"auth_method_settings": {
							"identity_url": "https://identity.example.com",
							"identity_tenant_subdomain": "test-tenant"
						}
					}
				}
			}`,
			expectedError: false,
			validateAuth: func(t *testing.T, authProfile *auth.IdsecAuthProfile) {
				if authProfile.AuthMethod != auth.IdentityServiceUser {
					t.Errorf("Expected IdentityServiceUser auth method, got %s", authProfile.AuthMethod)
				}
				settings, ok := authProfile.AuthMethodSettings.(*auth.IdentityServiceUserIdsecAuthMethodSettings)
				if !ok {
					t.Errorf("Expected IdentityServiceUserIdsecAuthMethodSettings, got %T", authProfile.AuthMethodSettings)
					return
				}
				if settings.IdentityURL != "https://identity.example.com" {
					t.Errorf("Expected identity URL 'https://identity.example.com', got '%s'", settings.IdentityURL)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var profile IdsecProfile
			err := json.Unmarshal([]byte(tt.jsonData), &profile)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Validate auth profile integration
			if tt.validateAuth != nil && len(profile.AuthProfiles) > 0 {
				for _, authProfile := range profile.AuthProfiles {
					tt.validateAuth(t, authProfile)
					break // Test first auth profile
				}
			}
		})
	}
}

// TestIdsecProfile_RoundTrip tests JSON marshaling and unmarshaling round trip
func TestIdsecProfile_RoundTrip(t *testing.T) {
	originalProfile := &IdsecProfile{
		ProfileName:        "roundtrip-test",
		ProfileDescription: "Test for JSON round trip",
		AuthProfiles: map[string]*auth.IdsecAuthProfile{
			"test": {
				Username:           "roundtrip@example.com",
				AuthMethod:         auth.Default,
				AuthMethodSettings: &auth.DefaultIdsecAuthMethodSettings{},
			},
		},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(originalProfile)
	if err != nil {
		t.Fatalf("Failed to marshal profile: %v", err)
	}

	// Unmarshal back to struct
	var unmarshaledProfile IdsecProfile
	err = json.Unmarshal(jsonData, &unmarshaledProfile)
	if err != nil {
		t.Fatalf("Failed to unmarshal profile: %v", err)
	}

	// Validate round trip
	if unmarshaledProfile.ProfileName != originalProfile.ProfileName {
		t.Errorf("ProfileName mismatch after round trip: expected '%s', got '%s'",
			originalProfile.ProfileName, unmarshaledProfile.ProfileName)
	}
	if unmarshaledProfile.ProfileDescription != originalProfile.ProfileDescription {
		t.Errorf("ProfileDescription mismatch after round trip: expected '%s', got '%s'",
			originalProfile.ProfileDescription, unmarshaledProfile.ProfileDescription)
	}
	if len(unmarshaledProfile.AuthProfiles) != len(originalProfile.AuthProfiles) {
		t.Errorf("AuthProfiles count mismatch after round trip: expected %d, got %d",
			len(originalProfile.AuthProfiles), len(unmarshaledProfile.AuthProfiles))
	}
}

func TestIdsecProfile_Validate(t *testing.T) {
	tests := []struct {
		name          string
		profile       *IdsecProfile
		expectedError bool
		errorContains string
		validateFunc  func(t *testing.T, err error)
	}{
		{
			name: "error_empty_auth_profiles",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles:       map[string]*auth.IdsecAuthProfile{},
			},
			expectedError: true,
			errorContains: "profile must have at least one auth profile configured",
		},
		{
			name: "error_nil_auth_profiles_map",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles:       nil,
			},
			expectedError: true,
			errorContains: "profile must have at least one auth profile configured",
		},
		{
			name: "error_unsupported_auth_method_direct",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"ap": {
						Username:           "u",
						AuthMethod:         auth.Direct,
						AuthMethodSettings: &auth.DirectIdsecAuthMethodSettings{},
					},
				},
			},
			expectedError: true,
			errorContains: "unsupported auth method",
		},
		{
			name: "error_unsupported_auth_method_other",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"other": {
						Username:           "u",
						AuthMethod:         auth.Other,
						AuthMethodSettings: nil,
					},
				},
			},
			expectedError: true,
			errorContains: "unsupported auth method",
		},
		{
			name: "success_one_isp_one_pvwa",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"isp": {
						Username:           "u1",
						AuthMethod:         auth.Identity,
						AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{},
					},
					"pvwa": {
						Username:   "u2",
						AuthMethod: auth.PVWA,
						AuthMethodSettings: &auth.PVWAIdsecAuthMethodSettings{
							PVWAURL:         "https://pvwa.example.com",
							PVWALoginMethod: auth.PVWALoginMethodCyberArk,
						},
					},
				},
			},
			expectedError: false,
		},
		{
			name: "success_single_identity",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"default": {
						Username:           "u@example.com",
						AuthMethod:         auth.Identity,
						AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{},
					},
				},
			},
			expectedError: false,
		},
		{
			name: "success_single_identity_service_user",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"svc": {
						Username:   "u@example.com",
						AuthMethod: auth.IdentityServiceUser,
						AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
							IdentityURL:                      "https://id.example.com",
							IdentityTenantSubdomain:          "t",
							IdentityAuthorizationApplication: "app",
						},
					},
				},
			},
			expectedError: false,
		},
		{
			name: "success_single_pvwa",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"pvwa": {
						Username:   "admin",
						AuthMethod: auth.PVWA,
						AuthMethodSettings: &auth.PVWAIdsecAuthMethodSettings{
							PVWAURL:         "https://pvwa.example.com",
							PVWALoginMethod: auth.PVWALoginMethodCyberArk,
						},
					},
				},
			},
			expectedError: false,
		},
		{
			name: "success_all_default",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"a": {
						Username:           "u",
						AuthMethod:         auth.Default,
						AuthMethodSettings: &auth.DefaultIdsecAuthMethodSettings{},
					},
				},
			},
			expectedError: false,
		},
		{
			name: "error_multiple_identity",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"a": {
						Username:           "u1@example.com",
						AuthMethod:         auth.Identity,
						AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{},
					},
					"b": {
						Username:           "u2@example.com",
						AuthMethod:         auth.Identity,
						AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{},
					},
				},
			},
			expectedError: true,
			errorContains: "profile can include only 1 ISP authenticator",
		},
		{
			name: "error_multiple_pvwa",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"a": {
						Username:   "u1",
						AuthMethod: auth.PVWA,
						AuthMethodSettings: &auth.PVWAIdsecAuthMethodSettings{
							PVWAURL:         "https://a.example.com",
							PVWALoginMethod: auth.PVWALoginMethodCyberArk,
						},
					},
					"b": {
						Username:   "u2",
						AuthMethod: auth.PVWA,
						AuthMethodSettings: &auth.PVWAIdsecAuthMethodSettings{
							PVWAURL:         "https://b.example.com",
							PVWALoginMethod: auth.PVWALoginMethodLDAP,
						},
					},
				},
			},
			expectedError: true,
			errorContains: "profile can include only 1 PVWA authenticator",
		},
		{
			name: "success_nil_entry_skipped",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"identity": {
						Username:           "u@example.com",
						AuthMethod:         auth.Identity,
						AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{},
					},
					"nil": nil,
				},
			},
			expectedError: false,
		},
		{
			name: "error_identity_and_identity_service_user",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"id": {
						Username:           "u1@example.com",
						AuthMethod:         auth.Identity,
						AuthMethodSettings: &auth.IdentityIdsecAuthMethodSettings{},
					},
					"svc": {
						Username:   "u2@example.com",
						AuthMethod: auth.IdentityServiceUser,
						AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
							IdentityURL:                      "https://id.example.com",
							IdentityTenantSubdomain:          "t",
							IdentityAuthorizationApplication: "app",
						},
					},
				},
			},
			expectedError: true,
			errorContains: "profile can include only 1 ISP authenticator",
		},
		{
			name: "error_multiple_identity_service_user",
			profile: &IdsecProfile{
				ProfileName:        "p",
				ProfileDescription: "d",
				AuthProfiles: map[string]*auth.IdsecAuthProfile{
					"svc1": {
						Username:   "u1@example.com",
						AuthMethod: auth.IdentityServiceUser,
						AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
							IdentityURL:                      "https://id1.example.com",
							IdentityTenantSubdomain:          "t1",
							IdentityAuthorizationApplication: "app1",
						},
					},
					"svc2": {
						Username:   "u2@example.com",
						AuthMethod: auth.IdentityServiceUser,
						AuthMethodSettings: &auth.IdentityServiceUserIdsecAuthMethodSettings{
							IdentityURL:                      "https://id2.example.com",
							IdentityTenantSubdomain:          "t2",
							IdentityAuthorizationApplication: "app2",
						},
					},
				},
			},
			expectedError: true,
			errorContains: "profile can include only 1 ISP authenticator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.profile.Validate()

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
				if tt.validateFunc != nil {
					tt.validateFunc(t, err)
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}
