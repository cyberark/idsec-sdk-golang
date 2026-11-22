package groupaccess

import (
	"errors"
	"reflect"
	"strings"
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

// newGroupAccessPolicyWithApproval builds a policy with the given location type, targets and access approval.
func newGroupAccessPolicyWithApproval(locationType string, targets groupaccessmodels.IdsecPolicyGroupAccessTarget, accessApproval *policycommonmodels.IdsecPolicyAccessApprovalCondition) *groupaccessmodels.IdsecPolicyGroupAccessPolicy {
	policy := newGroupAccessPolicy(locationType, targets)
	policy.Conditions.MaxSessionDuration = 1
	policy.Conditions.AccessApproval = accessApproval
	return policy
}

var approver = policycommonmodels.IdsecPolicyPrincipal{
	ID:                  "approver-id",
	Name:                "approver@cyberark.cloud.12345",
	Type:                policycommonmodels.PrincipalTypeUser,
	SourceDirectoryName: "CyberArk",
	SourceDirectoryID:   "12345",
}

// TestOmitEmptyAccessWindow covers dropping an unset access window from dual control payloads.
func TestOmitEmptyAccessWindow(t *testing.T) {
	required := &policycommonmodels.IdsecPolicyAccessApprovalCondition{Required: true, Approvers: []policycommonmodels.IdsecPolicyPrincipal{approver}}
	withWindow := func(policy *groupaccessmodels.IdsecPolicyGroupAccessPolicy) *groupaccessmodels.IdsecPolicyGroupAccessPolicy {
		policy.Conditions.AccessWindow = policycommonmodels.IdsecPolicyTimeCondition{DaysOfTheWeek: []int{1, 2, 3}, FromHour: "09:00:00", ToHour: "17:00:00"}
		return policy
	}
	tests := []struct {
		name           string
		policy         *groupaccessmodels.IdsecPolicyGroupAccessPolicy
		expectWindow   bool
		expectApproval bool
	}{
		{"success_gcp_required_empty_window_dropped", newGroupAccessPolicyWithApproval("GCP", gcpTargets, required), false, true},
		{"success_gcp_required_set_window_kept", withWindow(newGroupAccessPolicyWithApproval("GCP", gcpTargets, required)), true, true},
		{"success_gcp_without_approval_window_kept", newGroupAccessPolicyWithApproval("GCP", gcpTargets, nil), true, false},
		{"success_gcp_not_required_window_kept", newGroupAccessPolicyWithApproval("GCP", gcpTargets, &policycommonmodels.IdsecPolicyAccessApprovalCondition{Required: false}), true, true},
		{"success_azure_without_approval_unchanged", newGroupAccessPolicyWithApproval("Azure", azureTargets, nil), true, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			policyJSON, err := common.SerializeJSONCamel(tc.policy)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			omitEmptyAccessWindow(tc.policy, policyJSON)
			conditions, ok := policyJSON["conditions"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected conditions map, got %T", policyJSON["conditions"])
			}
			if _, exists := conditions["accessWindow"]; exists != tc.expectWindow {
				t.Fatalf("expected accessWindow present=%v, got %#v", tc.expectWindow, conditions)
			}
			rawApproval, exists := conditions["accessApproval"]
			if exists != tc.expectApproval {
				t.Fatalf("expected accessApproval present=%v, got %#v", tc.expectApproval, conditions)
			}
			if !exists || !tc.policy.Conditions.AccessApproval.Required {
				return
			}
			approval, ok := rawApproval.(map[string]interface{})
			if !ok || approval["required"] != true {
				t.Fatalf("expected required=true accessApproval, got %#v", rawApproval)
			}
			approvers, ok := approval["approvers"].([]interface{})
			if !ok || len(approvers) != 1 {
				t.Fatalf("expected one approver, got %#v", approval["approvers"])
			}
			first, _ := approvers[0].(map[string]interface{})
			if first["id"] != approver.ID || first["sourceDirectoryId"] != approver.SourceDirectoryID {
				t.Fatalf("unexpected approver payload: %#v", first)
			}
		})
	}
}

// TestCheckAccessApprovalSupported covers blocking dual control on Entra ID (Azure) group policies.
func TestCheckAccessApprovalSupported(t *testing.T) {
	required := &policycommonmodels.IdsecPolicyAccessApprovalCondition{Required: true, Approvers: []policycommonmodels.IdsecPolicyPrincipal{approver}}
	notRequired := &policycommonmodels.IdsecPolicyAccessApprovalCondition{Required: false}
	tests := []struct {
		name           string
		policy         *groupaccessmodels.IdsecPolicyGroupAccessPolicy
		expectErr      bool
		expectApproval bool
	}{
		{"error_azure_required", newGroupAccessPolicyWithApproval("Azure", azureTargets, required), true, false},
		{"error_azure_required_case_insensitive", newGroupAccessPolicyWithApproval("AZURE", azureTargets, required), true, false},
		{"success_azure_not_required_dropped", newGroupAccessPolicyWithApproval("Azure", azureTargets, notRequired), false, false},
		{"success_azure_without_approval", newGroupAccessPolicyWithApproval("Azure", azureTargets, nil), false, false},
		{"success_gcp_required_kept", newGroupAccessPolicyWithApproval("GCP", gcpTargets, required), false, true},
		{"success_gcp_not_required_kept", newGroupAccessPolicyWithApproval("GCP", gcpTargets, notRequired), false, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			policyJSON, err := common.SerializeJSONCamel(tc.policy)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertErrorMatch(t, checkAccessApprovalSupported(tc.policy, policyJSON), tc.expectErr,
				"dual control (access_approval.required=true) is not supported for Entra ID (Azure) group access policies; "+
					"it is supported for Google (GCP) groups only. Remove access_approval from the policy to create or update it")
			if tc.expectErr {
				return
			}
			conditions, ok := policyJSON["conditions"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected conditions map, got %T", policyJSON["conditions"])
			}
			if _, exists := conditions["accessApproval"]; exists != tc.expectApproval {
				t.Fatalf("expected accessApproval present=%v, got %#v", tc.expectApproval, conditions)
			}
		})
	}
}

// TestWrapAccessApprovalNotSupportedErr covers explaining backend dual control rejections.
func TestWrapAccessApprovalNotSupportedErr(t *testing.T) {
	backendErr := errors.New("failed to create policy - [400] - [Access approval is not supported]")
	otherErr := errors.New("failed to create policy - [400] - [invalid target]")
	required := &policycommonmodels.IdsecPolicyAccessApprovalCondition{Required: true}
	tests := []struct {
		name           string
		err            error
		accessApproval *policycommonmodels.IdsecPolicyAccessApprovalCondition
		expectWrapped  bool
	}{
		{"wrapped_required_not_supported", backendErr, required, true},
		{"unchanged_other_error", otherErr, required, false},
		{"unchanged_without_approval", backendErr, nil, false},
		{"unchanged_not_required", backendErr, &policycommonmodels.IdsecPolicyAccessApprovalCondition{Required: false}, false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := wrapAccessApprovalNotSupportedErr(tc.err, tc.accessApproval)
			if !errors.Is(err, tc.err) {
				t.Fatalf("expected wrapped error to retain %v, got %v", tc.err, err)
			}
			if wrapped := err != tc.err; wrapped != tc.expectWrapped {
				t.Fatalf("expected wrapped=%v, got %v", tc.expectWrapped, err)
			}
			if tc.expectWrapped && !strings.Contains(err.Error(), "is not enabled for this tenant") {
				t.Fatalf("expected tenant guidance in error, got %v", err)
			}
		})
	}
	if wrapAccessApprovalNotSupportedErr(nil, required) != nil {
		t.Fatalf("expected nil error to stay nil")
	}
}

// TestDecodeAccessApproval verifies access_approval returned by the API decodes into the conditions.
func TestDecodeAccessApproval(t *testing.T) {
	policyJSON := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":               "example-policy",
			"policy_entitlement": map[string]interface{}{"target_category": "Groups", "location_type": "GCP", "policy_type": "Recurring"},
		},
		"conditions": map[string]interface{}{
			"max_session_duration": 1,
			"access_approval": map[string]interface{}{
				"required": true,
				"approvers": []interface{}{
					map[string]interface{}{"id": "approver-id", "name": "approver@cyberark.cloud.12345", "type": "USER"},
				},
			},
		},
	}
	var policy groupaccessmodels.IdsecPolicyGroupAccessPolicy
	if err := mapstructure.Decode(policyJSON, &policy); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if policy.Conditions.MaxSessionDuration != 1 {
		t.Fatalf("expected max_session_duration 1, got %d", policy.Conditions.MaxSessionDuration)
	}
	accessApproval := policy.Conditions.AccessApproval
	if accessApproval == nil || !accessApproval.Required {
		t.Fatalf("expected required access approval, got %+v", accessApproval)
	}
	if len(accessApproval.Approvers) != 1 || accessApproval.Approvers[0].ID != "approver-id" {
		t.Fatalf("unexpected approvers: %+v", accessApproval.Approvers)
	}
}
