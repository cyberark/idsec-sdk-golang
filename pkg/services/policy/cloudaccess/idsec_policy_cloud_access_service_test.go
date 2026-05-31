package cloudaccess

import (
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	cloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
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

// TestServiceConfig verifies ServiceConfig method returns the global ServiceConfig value with minimal branching.
func TestServiceConfig(t *testing.T) {
	svc := &IdsecPolicyCloudAccessService{}
	if cfg := svc.ServiceConfig(); !reflect.DeepEqual(cfg, ServiceConfig) {
		t.Fatalf("service_config_mismatch: expected %+v got %+v", ServiceConfig, cfg)
	}
}

// evaluatePolicyStatus runs PolicyStatus and asserts results; extracted to reduce complexity in test function.
func evaluatePolicyStatus(t *testing.T, svc *IdsecPolicyCloudAccessService, req *policycommonmodels.IdsecPolicyGetPolicyStatus, expectErr bool, expectMsg string) {
	_, err := svc.PolicyStatus(req)
	assertErrorMatch(t, err, expectErr, expectMsg)
}

// TestPolicyStatus_validation covers validation error scenarios.
func TestPolicyStatus_validation(t *testing.T) {
	svc := &IdsecPolicyCloudAccessService{}
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
		caseData := tc // capture for closure
		t.Run(caseData.name, func(t *testing.T) {
			evaluatePolicyStatus(t, svc, caseData.req, caseData.expectErr, caseData.msg)
		})
	}
}

// TestNilInputPanics consolidates panic behavior tests for Create/Update/Delete policy methods.
func TestNilInputPanics(t *testing.T) {
	svc := &IdsecPolicyCloudAccessService{}
	tests := []struct {
		name string
		fn   func()
	}{
		{"create_policy_nil_panics", func() { _, _ = svc.CreatePolicy(nil) }},
		{"update_policy_nil_panics", func() { _, _ = svc.UpdatePolicy(nil) }},
		{"delete_policy_nil_panics", func() { _ = svc.DeletePolicy(nil) }},
	}
	for _, tc := range tests {
		caseData := tc
		t.Run(caseData.name, func(t *testing.T) {
			if !panicWrapper(caseData.fn) {
				t.Fatalf("expected panic for %s", caseData.name)
			}
		})
	}
}

func TestNormalizeCloudAccessApprovalPayload(t *testing.T) {
	tests := []struct {
		name              string
		approvalRequired  bool
		wantAccessWindow  bool
		wantDaysOfTheWeek bool
	}{
		{
			name:              "keeps_access_window_for_recurring_policy",
			approvalRequired:  false,
			wantAccessWindow:  true,
			wantDaysOfTheWeek: true,
		},
		{
			name:              "removes_access_window_when_approval_required",
			approvalRequired:  true,
			wantAccessWindow:  false,
			wantDaysOfTheWeek: false,
		},
	}

	for _, tc := range tests {
		caseData := tc
		t.Run(caseData.name, func(t *testing.T) {
			policy := &cloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy{
				Conditions: cloudaccessmodels.IdsecPolicyCloudAccessConditions{
					IdsecPolicyConditions: policycommonmodels.IdsecPolicyConditions{
						AccessWindow: policycommonmodels.IdsecPolicyTimeCondition{
							DaysOfTheWeek: []int{0, 1, 2, 3, 4, 5, 6},
							FromHour:      "09:00:00",
							ToHour:        "17:00:00",
						},
						MaxSessionDuration: 1,
					},
					AccessApproval: policycommonmodels.IdsecPolicyAccessApprovalCondition{
						Required: caseData.approvalRequired,
					},
				},
			}

			policyJSON, err := common.SerializeJSONCamel(policy)
			if err != nil {
				t.Fatalf("unexpected serialize error: %v", err)
			}
			normalizeCloudAccessApprovalPayload(policy, policyJSON)

			conditions, ok := policyJSON["conditions"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected conditions map, got %#v", policyJSON["conditions"])
			}
			accessWindow, hasAccessWindow := conditions["accessWindow"].(map[string]interface{})
			if hasAccessWindow != caseData.wantAccessWindow {
				t.Fatalf("accessWindow presence mismatch: got %v want %v", hasAccessWindow, caseData.wantAccessWindow)
			}
			_, hasDaysOfTheWeek := accessWindow["daysOfTheWeek"]
			if hasDaysOfTheWeek != caseData.wantDaysOfTheWeek {
				t.Fatalf("daysOfTheWeek presence mismatch: got %v want %v", hasDaysOfTheWeek, caseData.wantDaysOfTheWeek)
			}
		})
	}
}

// NOTE: Success-path tests require a mockable baseService; not available in current implementation.
// If dependency injection is introduced, extend tests to cover positive flows and list operations.
