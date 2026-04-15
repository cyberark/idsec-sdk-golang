package groupaccess

import (
	"reflect"
	"testing"

	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// assertErrorMatch validates an error presence and optional message.
func assertErrorMatch(t *testing.T, err error, expectErr bool, expectMsg string) {
	t.Helper()
	if expectErr {
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if expectMsg != "" && err.Error() != expectMsg {
			t.Fatalf("expected error msg '%s' got '%s'", expectMsg, err.Error())
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// panicWrapper executes fn returning true if a panic occurred.
func panicWrapper(fn func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	fn()
	return panicked
}

// TestServiceConfig verifies ServiceConfig method returns the global ServiceConfig value.
func TestServiceConfig(t *testing.T) {
	svc := &IdsecPolicyGroupAccessService{}
	if cfg := svc.ServiceConfig(); !reflect.DeepEqual(cfg, ServiceConfig) {
		t.Fatalf("service_config_mismatch: expected %+v got %+v", ServiceConfig, cfg)
	}
}

// evaluatePolicyStatus runs PolicyStatus and asserts results.
func evaluatePolicyStatus(t *testing.T, svc *IdsecPolicyGroupAccessService, req *policycommonmodels.IdsecPolicyGetPolicyStatus, expectErr bool, expectMsg string) {
	t.Helper()
	_, err := svc.PolicyStatus(req)
	assertErrorMatch(t, err, expectErr, expectMsg)
}

// TestPolicyStatus_validation covers validation error scenarios.
func TestPolicyStatus_validation(t *testing.T) {
	svc := &IdsecPolicyGroupAccessService{}
	tests := []struct {
		name      string
		req       *policycommonmodels.IdsecPolicyGetPolicyStatus
		expectErr bool
		msg       string
	}{
		{"error_nil_request", nil, true, "getPolicyStatus cannot be nil"},
		{"error_both_fields_empty", &policycommonmodels.IdsecPolicyGetPolicyStatus{}, true, "either PolicyID or PolicyName must be provided to retrieve policy status"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			evaluatePolicyStatus(t, svc, tc.req, tc.expectErr, tc.msg)
		})
	}
}

// TestNilInputPanics consolidates panic behavior tests for Create/Update/Delete policy methods.
func TestNilInputPanics(t *testing.T) {
	svc := &IdsecPolicyGroupAccessService{}
	tests := []struct {
		name string
		fn   func()
	}{
		{"create_policy_nil_panics", func() { _, _ = svc.CreatePolicy(nil) }},
		{"update_policy_nil_panics", func() { _, _ = svc.UpdatePolicy(nil) }},
		{"delete_policy_nil_panics", func() { _ = svc.DeletePolicy(nil) }},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if !panicWrapper(tc.fn) {
				t.Fatalf("expected panic for %s", tc.name)
			}
		})
	}
}

// NOTE: Success-path tests require a mockable baseService; not available in current implementation.
