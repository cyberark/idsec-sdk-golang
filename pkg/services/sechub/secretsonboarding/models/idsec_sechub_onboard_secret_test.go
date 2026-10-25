package models

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

func boolPtr(b bool) *bool { return &b }

func baseReq() *IdsecSecHubOnboardSecret {
	return &IdsecSecHubOnboardSecret{
		SourceStoreType: "AWS_ASM",
		TargetStoreType: "PAM_PCLOUD",
		SecretID:        "s-123",
		SecretValueType: "PLAINTEXT",
		SafeName:        "safe",
		PamAccount:      IdsecSecHubOnboardingPamAccount{Name: "acct", PlatformID: "Win"},
	}
}

func TestDiveAndOneofValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mutate      func(r *IdsecSecHubOnboardSecret)
		expectError bool
	}{
		{
			name:        "nil properties — omitempty skips dive",
			mutate:      func(r *IdsecSecHubOnboardSecret) {},
			expectError: false,
		},
		{
			name: "empty properties map — omitempty skips dive",
			mutate: func(r *IdsecSecHubOnboardSecret) {
				r.PamAccount.Properties = map[string]IdsecSecHubOnboardingPamAccountProperty{}
			},
			expectError: false,
		},
		{
			name: "valid VALUE property",
			mutate: func(r *IdsecSecHubOnboardSecret) {
				r.SecretValueType = "JSON"
				r.PamAccount.Properties = map[string]IdsecSecHubOnboardingPamAccountProperty{
					"username": {Type: "VALUE", Value: "admin"},
				}
			},
			expectError: false,
		},
		{
			name: "valid KEY_REF property",
			mutate: func(r *IdsecSecHubOnboardSecret) {
				r.SecretValueType = "JSON"
				r.PamAccount.Properties = map[string]IdsecSecHubOnboardingPamAccountProperty{
					"password": {Type: "KEY_REF", KeyRef: "pass"},
				}
			},
			expectError: false,
		},
		{
			name: "invalid property Type — caught by dive + oneof",
			mutate: func(r *IdsecSecHubOnboardSecret) {
				r.PamAccount.Properties = map[string]IdsecSecHubOnboardingPamAccountProperty{
					"username": {Type: "LITERAL"},
				}
			},
			expectError: true,
		},
		{
			name: "invalid SecretValueType — caught by oneof",
			mutate: func(r *IdsecSecHubOnboardSecret) {
				r.SecretValueType = "RAW"
			},
			expectError: true,
		},
		{
			name: "missing property Type — caught by required",
			mutate: func(r *IdsecSecHubOnboardSecret) {
				r.PamAccount.Properties = map[string]IdsecSecHubOnboardingPamAccountProperty{
					"username": {Value: "admin"},
				}
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := baseReq()
			tc.mutate(req)
			err := validation.ValidateStruct(req)
			if tc.expectError {
				require.Error(t, err, "expected validation error")
			} else {
				require.NoError(t, err, "expected no validation error")
			}
		})
	}
}
