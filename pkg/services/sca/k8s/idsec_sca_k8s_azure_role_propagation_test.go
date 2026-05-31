package k8s

import (
	"testing"
)

func TestAzureClusterScopeFromTargetID(t *testing.T) {
	t.Parallel()
	sub, scope, err := azureClusterScopeFromTargetID(
		"/subscriptions/efab8013-8ce1-4dfc-8463-b4da57f85921/resourcegroups/rg-ravish-cluster-new/providers/Microsoft.ContainerService/managedClusters/ravish-cluster-new-aad-2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if sub != "efab8013-8ce1-4dfc-8463-b4da57f85921" {
		t.Fatalf("subscription: got %q", sub)
	}
	if scope == "" {
		t.Fatal("expected non-empty scope")
	}
}

func TestAzureRoleDefinitionGUID(t *testing.T) {
	t.Parallel()
	guid, err := azureRoleDefinitionGUID(
		"/providers/Microsoft.Authorization/roleDefinitions/b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b",
	)
	if err != nil {
		t.Fatal(err)
	}
	if guid != "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b" {
		t.Fatalf("got %q", guid)
	}
}

func TestAzureRoleDefinitionsMatch(t *testing.T) {
	t.Parallel()
	full := "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b"
	if !azureRoleDefinitionsMatch(full, "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b") {
		t.Fatal("expected match")
	}
}
