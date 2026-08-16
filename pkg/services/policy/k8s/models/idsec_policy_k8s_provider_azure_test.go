package models

import (
	"testing"
)

// TestAzureTarget_roundTrip verifies that an Azure K8s target survives a
// Serialize -> Deserialize cycle with all fields (including read-only ones like ClusterName,
// NamespaceName, and Region) preserved.
func TestAzureTarget_roundTrip(t *testing.T) {
	t.Parallel()
	original := IdsecPolicyK8sAzureTarget{
		IdsecPolicyK8sTarget: IdsecPolicyK8sTarget{
			RoleID:        "role-123",
			WorkspaceID:   "workspace-456",
			RoleName:      "AzureRole",
			WorkspaceName: "Example Azure Workspace",
			Scope:         "cluster",
			ClusterID:     "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster",
			NamespaceID:   "ns-1",
			FQDN:          "https://example.aks.azure.com",
			ClusterName:   "aks-cluster",
			NamespaceName: "ns-name",
			Region:        "eastus",
		},
		OrgID:         "11111111-1111-1111-1111-111111111111",
		WorkspaceType: AzureWSTypeResource,
		RoleType:      1,
	}

	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("unexpected serialize error: %v", err)
	}

	var got IdsecPolicyK8sAzureTarget
	if err := got.Deserialize(data); err != nil {
		t.Fatalf("unexpected deserialize error: %v", err)
	}

	if got.IdsecPolicyK8sTarget != original.IdsecPolicyK8sTarget {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", got.IdsecPolicyK8sTarget, original.IdsecPolicyK8sTarget)
	}
	if got.OrgID != original.OrgID {
		t.Fatalf("org_id: got %q want %q", got.OrgID, original.OrgID)
	}
	if got.WorkspaceType != original.WorkspaceType {
		t.Fatalf("workspace_type: got %q want %q", got.WorkspaceType, original.WorkspaceType)
	}
	if got.RoleType != original.RoleType {
		t.Fatalf("role_type: got %d want %d", got.RoleType, original.RoleType)
	}
}
