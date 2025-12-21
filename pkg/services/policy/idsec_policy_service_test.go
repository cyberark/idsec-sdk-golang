package policy

import (
	"reflect"
	"testing"

	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// TestPolicyStatus_validation verifies input validation behavior of PolicyStatus.
// It exercises the error branches that do not require a live baseService.
func TestPolicyStatus_validation(t *testing.T) {
	tests := []struct {
		name            string
		input           *policycommonmodels.IdsecPolicyGetPolicyStatus
		expectsErr      bool
		expectsContains string
	}{
		{
			name:            "error_nil_input",
			input:           nil,
			expectsErr:      true,
			expectsContains: "getPolicyStatus cannot be nil",
		},
		{
			name: "error_empty_id_and_name",
			input: &policycommonmodels.IdsecPolicyGetPolicyStatus{
				PolicyID:   "",
				PolicyName: "",
			},
			expectsErr:      true,
			expectsContains: "either PolicyID or PolicyName must be provided to retrieve policy status",
		},
		// Note: cases with a non-empty PolicyID or PolicyName would exercise
		// the call to s.baseService.BasePolicyStatus which requires a functional
		// baseService and network/client mocks. Those are not covered here to
		// avoid changing production code.
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var svc IdsecPolicyService
			_, err := svc.PolicyStatus(tt.input)
			if tt.expectsErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.expectsContains != "" && !contains(err.Error(), tt.expectsContains) {
					t.Fatalf("expected error to contain '%s', got '%s'", tt.expectsContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestServiceConfig_return verifies that the ServiceConfig method returns the
// package-level ServiceConfig variable for IdsecPolicyService.
func TestServiceConfig_return(t *testing.T) {
	var svc IdsecPolicyService
	cfg := svc.ServiceConfig()
	if !reflect.DeepEqual(cfg, ServiceConfig) {
		t.Fatalf("expected ServiceConfig to equal package ServiceConfig variable")
	}
}

// contains is a small helper to check substring membership without importing strings
func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
