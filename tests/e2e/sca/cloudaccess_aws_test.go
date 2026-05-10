//go:build (e2e && sca) || e2e

package sca

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
	scacloudaccesssvc "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// ---------------------------------------------------------------------------
// ListTargets pagination test
// ---------------------------------------------------------------------------

// TestCloudAccessAWSListTargetsWithNextToken creates multiple eligible targets,
// then pages through results using limit=1 to verify nextToken handling.
func TestCloudAccessAWSListTargetsWithNextToken(t *testing.T) {
	testCtx := setupCloudAccessListTargetsTest(t, awsCloudAccessListTargetsConfig, false)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: CloudAccess AWS ListTargets pagination")

		policySvc := mustPolicyCloudAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		createdPolicyIDs := createCloudAccessPaginationPolicies(t, policySvc, awsCloudAccessListTargetsConfig, testCtx, principal)
		defer func() {
			for _, policyID := range createdPolicyIDs {
				deletePolicyBestEffort(t, policyID, policySvc.DeletePolicy)
			}
		}()

		cloudAccessSvc := mustPrincipalCloudAccessService(t, testCtx)
		page1, page2 := listCloudAccessTargetsWithNextToken(t, cloudAccessSvc, awsCloudAccessListTargetsConfig)
		verifyCloudAccessPagination(t, page1, page2)
	}, scacloudaccesssvc.ServiceConfig, cloudaccess.ServiceConfig)
}

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestCloudAccessAWSListTargets(t *testing.T) {
	testCtx := setupCloudAccessListTargetsTest(t, awsCloudAccessListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: CloudAccess AWS ListTargets")

		policySvc := mustPolicyCloudAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		target := cloudAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := createCloudAccessPolicy(t, policySvc, awsCloudAccessListTargetsConfig, principal, target, awsCloudAccessListTargetsConfig.policyNamePrefix)
		defer deletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		fetchedPolicy := getCloudAccessPolicy(t, policySvc, createdPolicyID)
		cloudAccessSvc := mustPrincipalCloudAccessService(t, testCtx)
		filteredResp := listCloudAccessTargets(t, cloudAccessSvc, awsCloudAccessListTargetsConfig.csp, target.WorkspaceID, 20)
		verifyCloudAccessFilteredTargets(t, awsCloudAccessListTargetsConfig, fetchedPolicy, target, filteredResp)
	}, scacloudaccesssvc.ServiceConfig, cloudaccess.ServiceConfig)
}

func TestCloudAccessAWSElevate(t *testing.T) {
	testCtx := setupCloudAccessListTargetsTest(t, awsCloudAccessListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: CloudAccess AWS Elevate")

		policySvc := mustPolicyCloudAccessService(t, ctx)
		principal := cloudAccessPrincipalFromConfig(t, testCtx)
		target := cloudAccessTargetFromConfig(t, testCtx, 0)
		createdPolicyID := createCloudAccessPolicy(t, policySvc, awsCloudAccessListTargetsConfig, principal, target, "sca_cli_cloudaccess_aws_elevate_e2e")
		defer deletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		cloudAccessSvc := mustPrincipalCloudAccessService(t, testCtx)
		elevateResp := elevateCloudAccessTarget(t, cloudAccessSvc, awsCloudAccessListTargetsConfig, target)
		verifyAWSCloudAccessElevate(t, elevateResp, target)
	}, scacloudaccesssvc.ServiceConfig, cloudaccess.ServiceConfig)
}
