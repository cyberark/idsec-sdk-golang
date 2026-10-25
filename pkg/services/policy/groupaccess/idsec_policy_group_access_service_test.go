package groupaccess

import (
	"reflect"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	groupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess/models"
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

// newGroupAccessPolicy builds a policy with the given location type and targets for target hook tests.
func newGroupAccessPolicy(locationType string, targets groupaccessmodels.IdsecPolicyGroupAccessTarget) *groupaccessmodels.IdsecPolicyGroupAccessPolicy {
	return &groupaccessmodels.IdsecPolicyGroupAccessPolicy{
		IdsecPolicyCommonAccessPolicy: policycommonmodels.IdsecPolicyCommonAccessPolicy{
			Metadata: policycommonmodels.IdsecPolicyMetadata{
				Name: "example-policy",
				PolicyEntitlement: policycommonmodels.IdsecPolicyEntitlement{
					TargetCategory: commonmodels.CategoryTypeGroupAccess,
					LocationType:   locationType,
					PolicyType:     policycommonmodels.PolicyTypeRecurring,
				},
			},
		},
		Targets: targets,
	}
}

var (
	azureTargets = groupaccessmodels.IdsecPolicyGroupAccessTarget{
		Targets: []groupaccessmodels.IdsecPolicyGroupAccessAzureTarget{{GroupID: "11111111-1111-1111-1111-111111111111", DirectoryID: "22222222-2222-2222-2222-222222222222", GroupName: "azure-group"}},
	}
	gcpTargets = groupaccessmodels.IdsecPolicyGroupAccessTarget{
		GCPTargets: []groupaccessmodels.IdsecPolicyGroupAccessGCPTarget{{GroupID: "groups/01234abcde", OrganizationID: "123456789012", OrganizationName: "Example Org"}},
	}
)

// TestSerializeTargets covers the create/update payload hook for Azure, GCP and mismatches.
func TestSerializeTargets(t *testing.T) {
	t.Run("success_azure_payload_unchanged", func(t *testing.T) {
		policy := newGroupAccessPolicy("Azure", azureTargets)
		legacyJSON, err := common.SerializeJSONCamel(policy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		legacy := legacyJSON["targets"]
		policyJSON, err := common.SerializeJSONCamel(policy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := serializeTargets(policy, policyJSON); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(policyJSON["targets"], legacy) {
			t.Fatalf("azure targets payload changed:\nlegacy: %#v\nnew:    %#v", legacy, policyJSON["targets"])
		}
	})

	t.Run("success_gcp_flat_targets", func(t *testing.T) {
		policy := newGroupAccessPolicy("GCP", gcpTargets)
		policyJSON, err := common.SerializeJSONCamel(policy)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := serializeTargets(policy, policyJSON); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := map[string]interface{}{
			"targets": []interface{}{
				map[string]interface{}{"groupId": "groups/01234abcde", "organizationId": "123456789012"},
			},
		}
		if !reflect.DeepEqual(policyJSON["targets"], expected) {
			t.Fatalf("expected %#v, got %#v", expected, policyJSON["targets"])
		}
	})

	mismatches := []struct {
		name      string
		policy    *groupaccessmodels.IdsecPolicyGroupAccessPolicy
		expectMsg string
	}{
		{"error_gcp_targets_azure_location", newGroupAccessPolicy("Azure", gcpTargets), "location_type Azure requires targets, got gcp_targets"},
		{"error_azure_targets_gcp_location", newGroupAccessPolicy("GCP", azureTargets), "location_type GCP requires gcp_targets, got targets"},
	}
	for _, tc := range mismatches {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			policyJSON, err := common.SerializeJSONCamel(tc.policy)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertErrorMatch(t, serializeTargets(tc.policy, policyJSON), true, tc.expectMsg)
		})
	}
}

// TestDeserializeTargets covers the read hook routing GCP items into gcp_targets.
func TestDeserializeTargets(t *testing.T) {
	policyJSON := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":               "example-policy",
			"policy_entitlement": map[string]interface{}{"target_category": "Groups", "location_type": "GCP", "policy_type": "Recurring"},
		},
		"targets": map[string]interface{}{
			"targets": []interface{}{
				map[string]interface{}{"group_id": "groups/01234abcde", "organization_id": "123456789012", "organization_name": "Example Org"},
			},
		},
	}
	var policy groupaccessmodels.IdsecPolicyGroupAccessPolicy
	if err := mapstructure.Decode(policyJSON, &policy); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if err := deserializeTargets(&policy, policyJSON); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(policy.Targets.Targets) != 0 {
		t.Fatalf("expected no azure targets, got %+v", policy.Targets.Targets)
	}
	if !reflect.DeepEqual(policy.Targets.GCPTargets, gcpTargets.GCPTargets) {
		t.Fatalf("unexpected gcp targets: %+v", policy.Targets.GCPTargets)
	}
}
