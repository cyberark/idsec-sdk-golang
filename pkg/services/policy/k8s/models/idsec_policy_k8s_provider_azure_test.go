package models

import (
	"testing"
)

// TestAzureTarget_roundTrip verifies that an Azure K8s target survives a
// Serialize -> Deserialize cycle with all fields (including read-only ones like ClusterName
// and NamespaceName) preserved.
func TestAzureTarget_roundTrip(t *testing.T) {
	t.Parallel()
	original := IdsecPolicyK8sAzureTarget{
		IdsecPolicyK8sSharedTarget: IdsecPolicyK8sSharedTarget{
			Scope:         "cluster",
			NamespaceID:   "ns-1",
			FQDN:          "https://example.aks.azure.com",
			NamespaceName: "ns-name",
		},
		RoleID:        "role-123",
		WorkspaceID:   "workspace-456",
		RoleName:      "AzureRole",
		WorkspaceName: "Example Azure Workspace",
		ClusterID:     "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster",
		ClusterName:   "aks-cluster",
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

	if got != original {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", got, original)
	}
}
