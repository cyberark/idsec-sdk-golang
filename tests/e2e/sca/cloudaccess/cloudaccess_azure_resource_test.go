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
// Full E2E flow
// ---------------------------------------------------------------------------

func TestCloudAccessAzureResourceListTargets(t *testing.T) {
	t.Skip("Azure CloudAccess tests are temporarily disabled")

	framework.LogSection(t, "Test: CloudAccess Azure Resource ListTargets")

	testCtx := scahelpers.SetupCloudAccessListTargetsTest(t, scahelpers.AzureResourceCloudAccessListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		policySvc := scahelpers.MustPolicyCloudAccessService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		target := scahelpers.CloudAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := scahelpers.CreateCloudAccessPolicy(t, policySvc, scahelpers.AzureResourceCloudAccessListTargetsConfig, principal, target, scahelpers.AzureResourceCloudAccessListTargetsConfig.PolicyNamePrefix)
		defer scahelpers.DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := scahelpers.GetCloudAccessPolicy(t, policySvc, createdPolicyID)
		cloudAccessSvc := scahelpers.MustPrincipalCloudAccessService(t, testCtx)
		filteredResp := scahelpers.ListCloudAccessTargets(t, cloudAccessSvc, scahelpers.AzureResourceCloudAccessListTargetsConfig.CSP, target.WorkspaceID, 20)
		scahelpers.VerifyCloudAccessFilteredTargets(t, scahelpers.AzureResourceCloudAccessListTargetsConfig, fetchedPolicy, target, filteredResp)
	}, scacloudaccesssvc.ServiceConfig, policycloudaccess.ServiceConfig)
}

func TestCloudAccessAzureResourceElevate(t *testing.T) {
	t.Skip("Azure CloudAccess tests are temporarily disabled")

	const (
		displayName      = "CloudAccess Azure Resource Elevate"
		policyNamePrefix = "sca_cli_cloudaccess_azure_resource_elevate_e2e"
	)

	framework.LogSection(t, "Test: "+displayName)

	framework.Run(t, func(ctx *framework.TestContext) {
		testCtx := scahelpers.SetupCloudAccessListTargetsTest(t, scahelpers.AzureResourceCloudAccessListTargetsConfig, true)
		scahelpers.RunAzureCloudAccessElevateTest(t, ctx, testCtx, scahelpers.AzureResourceCloudAccessListTargetsConfig, displayName, policyNamePrefix)
	}, scacloudaccesssvc.ServiceConfig, policycloudaccess.ServiceConfig)
}
