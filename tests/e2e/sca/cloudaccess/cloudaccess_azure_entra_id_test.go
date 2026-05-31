//go:build (e2e && sca) || e2e

package cloudaccess

import (
	"testing"

	policycloudaccess "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
	scacloudaccesssvc "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
	scahelpers "github.com/cyberark/idsec-sdk-golang/tests/e2e/sca"
)

// ---------------------------------------------------------------------------
// ListTargets pagination test
// ---------------------------------------------------------------------------

// TestCloudAccessAzureEntraIDListTargetsWithNextToken creates multiple eligible targets,
// then pages through results using limit=1 to verify nextToken handling.
func TestCloudAccessAzureEntraIDListTargetsWithNextToken(t *testing.T) {
	t.Skip("Azure CloudAccess tests are temporarily disabled")

	framework.LogSection(t, "Test: CloudAccess Azure Entra ID ListTargets pagination")

	testCtx := scahelpers.SetupCloudAccessListTargetsTest(t, scahelpers.AzureEntraIDCloudAccessListTargetsConfig, false)

	framework.Run(t, func(ctx *framework.TestContext) {
		policySvc := scahelpers.MustPolicyCloudAccessService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		createdPolicyIDs := scahelpers.CreateCloudAccessPaginationPolicies(t, policySvc, scahelpers.AzureEntraIDCloudAccessListTargetsConfig, testCtx, principal)
		defer func() {
			for _, policyID := range createdPolicyIDs {
				scahelpers.DeletePolicyBestEffort(t, policyID, policySvc.DeletePolicy)
			}
		}()

		cloudAccessSvc := scahelpers.MustPrincipalCloudAccessService(t, testCtx)
		page1, page2 := scahelpers.ListCloudAccessTargetsWithNextToken(t, cloudAccessSvc, scahelpers.AzureEntraIDCloudAccessListTargetsConfig)
		scahelpers.VerifyCloudAccessPagination(t, page1, page2)
	}, scacloudaccesssvc.ServiceConfig, policycloudaccess.ServiceConfig)
}

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestCloudAccessAzureEntraIDListTargets(t *testing.T) {
	t.Skip("Azure CloudAccess tests are temporarily disabled")

	framework.LogSection(t, "Test: CloudAccess Azure Entra ID ListTargets")

	testCtx := scahelpers.SetupCloudAccessListTargetsTest(t, scahelpers.AzureEntraIDCloudAccessListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		policySvc := scahelpers.MustPolicyCloudAccessService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		target := scahelpers.CloudAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := scahelpers.CreateCloudAccessPolicy(t, policySvc, scahelpers.AzureEntraIDCloudAccessListTargetsConfig, principal, target, scahelpers.AzureEntraIDCloudAccessListTargetsConfig.PolicyNamePrefix)
		defer scahelpers.DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := scahelpers.GetCloudAccessPolicy(t, policySvc, createdPolicyID)
		cloudAccessSvc := scahelpers.MustPrincipalCloudAccessService(t, testCtx)
		filteredResp := scahelpers.ListCloudAccessTargets(t, cloudAccessSvc, scahelpers.AzureEntraIDCloudAccessListTargetsConfig.CSP, target.WorkspaceID, 20)
		scahelpers.VerifyCloudAccessFilteredTargets(t, scahelpers.AzureEntraIDCloudAccessListTargetsConfig, fetchedPolicy, target, filteredResp)
	}, scacloudaccesssvc.ServiceConfig, policycloudaccess.ServiceConfig)
}

func TestCloudAccessAzureEntraIDElevate(t *testing.T) {
	t.Skip("Azure CloudAccess tests are temporarily disabled")

	const (
		displayName      = "CloudAccess Azure Entra ID Elevate"
		policyNamePrefix = "sca_cli_cloudaccess_azure_entra_id_elevate_e2e"
	)

	framework.LogSection(t, "Test: "+displayName)

	framework.Run(t, func(ctx *framework.TestContext) {
		testCtx := scahelpers.SetupCloudAccessListTargetsTest(t, scahelpers.AzureEntraIDCloudAccessListTargetsConfig, true)
		scahelpers.RunAzureCloudAccessElevateTest(t, ctx, testCtx, scahelpers.AzureEntraIDCloudAccessListTargetsConfig, displayName, policyNamePrefix)
	}, scacloudaccesssvc.ServiceConfig, policycloudaccess.ServiceConfig)
}
