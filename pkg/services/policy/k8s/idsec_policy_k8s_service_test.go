package k8s

import (
	"reflect"
	"testing"

	policycommon "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policyk8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/k8s/models"
)

func assertErrorMatch(t *testing.T, err error, expectErr bool, expectMsg string) {
	t.Helper()
	if expectErr {
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if expectMsg != "" && err.Error() != expectMsg {
			t.Fatalf("expected error msg %q got %q", expectMsg, err.Error())
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func panicWrapper(fn func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	fn()
	return panicked
}

func TestServiceConfig(t *testing.T) {
	t.Parallel()
	svc := &IdsecPolicyK8sService{}
	if cfg := svc.ServiceConfig(); !reflect.DeepEqual(cfg, ServiceConfig) {
		t.Fatalf("service_config_mismatch: expected %+v got %+v", ServiceConfig, cfg)
	}
}

func TestPolicyStatus_validation(t *testing.T) {
	t.Parallel()
	svc := &IdsecPolicyK8sService{}
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.PolicyStatus(tc.req)
			assertErrorMatch(t, err, tc.expectErr, tc.msg)
		})
	}
}

func TestTfPolicyStatus_validation(t *testing.T) {
	t.Parallel()
	svc := &IdsecPolicyK8sService{}
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.TfPolicyStatus(tc.req)
			assertErrorMatch(t, err, tc.expectErr, tc.msg)
		})
	}
}

func TestNilInputPanics(t *testing.T) {
	t.Parallel()
	svc := &IdsecPolicyK8sService{}
	tests := []struct {
		name string
		fn   func()
	}{
		{"create_policy_nil_panics", func() { _, _ = svc.CreatePolicy(nil) }},
		{"update_policy_nil_panics", func() { _, _ = svc.UpdatePolicy(nil) }},
		{"delete_policy_nil_panics", func() { _ = svc.DeletePolicy(nil) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !panicWrapper(tc.fn) {
				t.Fatalf("expected panic for %s", tc.name)
			}
		})
	}
}

func TestDecodePolicyPage_azureTarget(t *testing.T) {
	t.Parallel()
	svc := &IdsecPolicyK8sService{}
	policyID := "azure_resource_cluster_example"
	policyName := "example-k8s-policy"
	rawPolicy := map[string]interface{}{
		"metadata": map[string]interface{}{
			"policy_id": policyID,
			"name":      policyName,
		},
		"targets": map[string]interface{}{
			"targets": []interface{}{
				map[string]interface{}{
					"workspace_type": policyk8smodels.AzureWSTypeResource,
					"role_id":        "role-123",
					"workspace_id":   "workspace-456",
					"scope":          "cluster",
					"cluster_id":     "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster",
					"org_id":         "11111111-1111-1111-1111-111111111111",
				},
			},
		},
	}
	page := &policycommon.IdsecPolicyBasePolicyPage{
		Items: []*map[string]interface{}{&rawPolicy},
	}
	decoded := svc.decodePolicyPage(page)
	if decoded == nil {
		t.Fatal("expected non-nil decoded page")
	}
	if len(decoded.Items) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(decoded.Items))
	}
	policy := decoded.Items[0]
	if policy == nil {
		t.Fatal("expected non-nil policy")
	}
	if policy.Metadata.PolicyID != policyID {
		t.Fatalf("policy_id: got %q want %q", policy.Metadata.PolicyID, policyID)
	}
	if policy.Metadata.Name != policyName {
		t.Fatalf("name: got %q want %q", policy.Metadata.Name, policyName)
	}
	if len(policy.Targets.AzureTargets) != 1 {
		t.Fatalf("expected 1 azure target, got %d", len(policy.Targets.AzureTargets))
	}
	if policy.Targets.AzureTargets[0].ClusterID == "" {
		t.Fatal("expected cluster_id on azure target")
	}
}

// NOTE: Success-path tests for ListPoliciesBy, TfListPoliciesBy, and PolicyStatus require a
// mockable baseService; not available without dependency injection or HTTP mocks.
