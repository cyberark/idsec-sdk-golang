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

// TestCloudAccessAWSListTargetsWithNextToken creates multiple eligible targets,
// then pages through results using limit=1 to verify nextToken handling.
func TestCloudAccessAWSListTargetsWithNextToken(t *testing.T) {
	t.Skip("AWS CloudAccess tests are temporarily disabled")

	framework.LogSection(t, "Test: CloudAccess AWS ListTargets pagination")

	testCtx := scahelpers.SetupCloudAccessListTargetsTest(t, scahelpers.AWSCloudAccessListTargetsConfig, false)

	framework.Run(t, func(ctx *framework.TestContext) {
		policySvc := scahelpers.MustPolicyCloudAccessService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		createdPolicyIDs := scahelpers.CreateCloudAccessPaginationPolicies(t, policySvc, scahelpers.AWSCloudAccessListTargetsConfig, testCtx, principal)
		defer func() {
			for _, policyID := range createdPolicyIDs {
				scahelpers.DeletePolicyBestEffort(t, policyID, policySvc.DeletePolicy)
			}
		}()

		cloudAccessSvc := scahelpers.MustPrincipalCloudAccessService(t, testCtx)
		page1, page2 := scahelpers.ListCloudAccessTargetsWithNextToken(t, cloudAccessSvc, scahelpers.AWSCloudAccessListTargetsConfig)
		scahelpers.VerifyCloudAccessPagination(t, page1, page2)
	}, scacloudaccesssvc.ServiceConfig, policycloudaccess.ServiceConfig)
}

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestCloudAccessAWSListTargets(t *testing.T) {
	t.Skip("AWS CloudAccess tests are temporarily disabled")

	framework.LogSection(t, "Test: CloudAccess AWS ListTargets")

	testCtx := scahelpers.SetupCloudAccessListTargetsTest(t, scahelpers.AWSCloudAccessListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		policySvc := scahelpers.MustPolicyCloudAccessService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		target := scahelpers.CloudAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := scahelpers.CreateCloudAccessPolicy(t, policySvc, scahelpers.AWSCloudAccessListTargetsConfig, principal, target, scahelpers.AWSCloudAccessListTargetsConfig.PolicyNamePrefix)
		defer scahelpers.DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := scahelpers.GetCloudAccessPolicy(t, policySvc, createdPolicyID)
		cloudAccessSvc := scahelpers.MustPrincipalCloudAccessService(t, testCtx)
		filteredResp := scahelpers.ListCloudAccessTargets(t, cloudAccessSvc, scahelpers.AWSCloudAccessListTargetsConfig.CSP, target.WorkspaceID, 20)
		scahelpers.VerifyCloudAccessFilteredTargets(t, scahelpers.AWSCloudAccessListTargetsConfig, fetchedPolicy, target, filteredResp)
	}, scacloudaccesssvc.ServiceConfig, policycloudaccess.ServiceConfig)
}

func TestCloudAccessAWSElevate(t *testing.T) {
	t.Skip("AWS CloudAccess tests are temporarily disabled")

	framework.LogSection(t, "Test: CloudAccess AWS Elevate")

	testCtx := scahelpers.SetupCloudAccessListTargetsTest(t, scahelpers.AWSCloudAccessListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		policySvc := scahelpers.MustPolicyCloudAccessService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		target := scahelpers.CloudAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := scahelpers.CreateCloudAccessPolicy(t, policySvc, scahelpers.AWSCloudAccessListTargetsConfig, principal, target, "sca_cli_cloudaccess_aws_elevate_e2e")
		defer scahelpers.DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		cloudAccessSvc := scahelpers.MustPrincipalCloudAccessService(t, testCtx)
		elevateResp := scahelpers.ElevateCloudAccessTarget(t, cloudAccessSvc, scahelpers.AWSCloudAccessListTargetsConfig, target)
		scahelpers.VerifyAWSCloudAccessElevate(t, elevateResp, target)
	}, scacloudaccesssvc.ServiceConfig, policycloudaccess.ServiceConfig)
}
