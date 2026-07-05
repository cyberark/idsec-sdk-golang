package k8s

import (
	"os"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
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

func TestKubectlLoginLogLevelEnabled_respectsKUBELOGINOverSDKLogLevel(t *testing.T) {
	origPrivate, hadPrivate := os.LookupEnv(KubectlLoginLogLevelEnvVar)
	origSDK, hadSDK := os.LookupEnv(config.IdsecLogLevelEnvVar)
	t.Cleanup(func() {
		restoreEnv(KubectlLoginLogLevelEnvVar, origPrivate, hadPrivate)
		restoreEnv(config.IdsecLogLevelEnvVar, origSDK, hadSDK)
	})

	t.Run("private_info_suppresses_debug", func(t *testing.T) {
		t.Setenv(KubectlLoginLogLevelEnvVar, "info")
		t.Setenv(config.IdsecLogLevelEnvVar, "debug")
		if KubectlLoginLogLevelEnabled(KubectlLoginLogLevelDebug) {
			t.Fatal("expected DEBUG to be disabled at private INFO level")
		}
		if !KubectlLoginLogLevelEnabled(KubectlLoginLogLevelInfo) {
			t.Fatal("expected INFO to be enabled at private INFO level")
		}
	})

	t.Run("private_debug_includes_info_and_debug", func(t *testing.T) {
		t.Setenv(KubectlLoginLogLevelEnvVar, "debug")
		t.Setenv(config.IdsecLogLevelEnvVar, "info")
		if !KubectlLoginLogLevelEnabled(KubectlLoginLogLevelDebug) {
			t.Fatal("expected DEBUG to be enabled at private DEBUG level")
		}
		if !KubectlLoginLogLevelEnabled(KubectlLoginLogLevelInfo) {
			t.Fatal("expected INFO to be enabled at private DEBUG level")
		}
	})
}

func restoreEnv(key, value string, ok bool) {
	if ok {
		_ = os.Setenv(key, value)
		return
	}
	_ = os.Unsetenv(key)
}
