//go:build (e2e && sca) || e2e

package sca

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess"
	groupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sca/entragroups"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// ---------------------------------------------------------------------------
// ListTargets pagination test
// ---------------------------------------------------------------------------

// TestEntraGroupsListTargetsWithNextToken pages through results using
// limit=1 and principal auth to obtain a nextToken, then fetches the next page.
func TestEntraGroupsListTargetsWithNextToken(t *testing.T) {
	skipUnlessSupportedSCAEnv(t)

	// Step 1: Load config and extract principal.
	cfg := LoadSCATestConfig(t)
	entraCfg := cspBlock(cfg, "azure_entra_groups")
	authCfg := cspBlock(cfg, "auth")
	require.NotNil(t, entraCfg, "azure_entra_groups block is required in JSON config")
	require.NotNil(t, authCfg, "auth block is required in JSON config")

	principal := principalBlock(entraCfg)
	require.NotNil(t, principal, "azure_entra_groups.principal block is required")

	// Step 2: Authenticate as principal and build Entra Groups service.
	principalSvc, err := buildPrincipalEntraGroupsService(t, authCfg, principal)
	require.NoError(t, err)

	// Step 3: Fetch first page with limit=1 to trigger pagination.
	page1, err := principalSvc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:   "AZURE",
		Limit: 1,
	})
	require.NoError(t, err)

	// Step 4: If nextToken is empty, there is only one page — nothing more to test.
	if page1.NextToken == "" {
		t.Log("No nextToken returned; only one page of results")
		return
	}

	// Step 5: Fetch second page using the nextToken from page 1.
	page2, err := principalSvc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:       "AZURE",
		Limit:     1,
		NextToken: page1.NextToken,
	})
	require.NoError(t, err)
	t.Logf("Pagination: page1=%d groups, page2=%d groups, nextToken=%q",
		len(page1.Response), len(page2.Response), page2.NextToken)
}

// ---------------------------------------------------------------------------
// Full E2E flow
// ---------------------------------------------------------------------------

func TestEntraGroupsAzureListTargets(t *testing.T) {
	skipUnlessSupportedSCAEnv(t)

	cfg := LoadSCATestConfig(t)
	entraCfg := cspBlock(cfg, "azure_entra_groups")
	authCfg := cspBlock(cfg, "auth")
	require.NotNil(t, entraCfg, "azure_entra_groups block is required in JSON config")
	require.NotNil(t, authCfg, "auth block is required in JSON config")

	principal := principalBlock(entraCfg)
	require.NotNil(t, principal, "azure_entra_groups.principal block is required")

	targets := configTargets(entraCfg)
	require.NotEmpty(t, targets, "azure_entra_groups.targets.targets array is required")

	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Azure Entra Groups ListTargets")

		policySvc, err := ctx.API.PolicyGroupaccess()
		require.NoError(t, err)

		// ── Step 1: Read principal from config ────────────────────────
		principalID := strVal(principal, "principal_id")
		principalName := strVal(principal, "principal_name")
		srcDirName := strVal(principal, "source_directory_name")
		srcDirID := strVal(principal, "source_directory_id")
		t.Logf("Using principal from config: %s (%s)", principalName, principalID)

		// ── Step 2: Read first target from config ─────────────────────
		tgt := targets[0]
		target := groupaccessmodels.IdsecPolicyGroupAccessTargetItem{
			GroupID:     strVal(tgt, "group_id"),
			DirectoryID: strVal(tgt, "directory_id"),
			GroupName:   strVal(tgt, "group_name"),
		}
		require.NotEmpty(t, target.GroupID, "group_id is required for azure_entra_groups target")
		require.NotEmpty(t, target.DirectoryID, "directory_id is required for azure_entra_groups target")
		t.Logf("Using target from config: groupId=%s directoryId=%s groupName=%s",
			target.GroupID, target.DirectoryID, target.GroupName)

		// ── Step 3: Create policy ─────────────────────────────────────
		const policyNamePrefix = "sca_cli_azure_entra_groups_e2e"
		policyName := buildPolicyName(policyNamePrefix, principalName)
		createdPolicy, err := policySvc.CreatePolicy(
			buildAzureEntraGroupsPolicyFromBodyTemplate(policyName, principalID, principalName, srcDirName, srcDirID, target),
		)
		require.NoError(t, err)
		require.NotNil(t, createdPolicy)
		require.NotEmpty(t, createdPolicy.Metadata.PolicyID)
		createdPolicyID := createdPolicy.Metadata.PolicyID
		t.Logf("Policy created - ID: %s, Name: %s", createdPolicy.Metadata.PolicyID, policyName)

		err = waitForPolicyActive(t, createdPolicy.Metadata.PolicyID, func() (string, error) {
			p, e := policySvc.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
				PolicyID: createdPolicy.Metadata.PolicyID,
			})
			if e != nil || p == nil {
				return "", e
			}
			return p.Metadata.Status.Status, nil
		})
		require.NoError(t, err)

		fetchedPolicy, err := policySvc.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
			PolicyID: createdPolicy.Metadata.PolicyID,
		})
		require.NoError(t, err)
		require.NotNil(t, fetchedPolicy)

		require.Equal(t, createdPolicyID, fetchedPolicy.Metadata.PolicyID, "GetPolicy: policy ID mismatch")
		require.NotEmpty(t, fetchedPolicy.Metadata.Name, "GetPolicy: name should not be empty")
		require.Equal(t, "Active", strings.TrimSpace(fetchedPolicy.Metadata.Status.Status), "GetPolicy: status should be Active")
		t.Log("Policy validated via GetPolicy")

		// ── Step 4: List targets and verify target appears ────────────
		principalEntraGroupsSvc, err := buildPrincipalEntraGroupsService(t, authCfg, principal)
		require.NoError(t, err)

		listTargetsResp, err := principalEntraGroupsSvc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
			CSP:         "AZURE",
			WorkspaceID: target.DirectoryID,
			Limit:       5,
		})
		require.NoError(t, err)
		require.NotNil(t, listTargetsResp)
		t.Logf("ListTargets returned %d groups for directoryId=%s total=%d nextToken=%q",
			len(listTargetsResp.Response), target.DirectoryID, listTargetsResp.Total, listTargetsResp.NextToken)
		verifyEntraGroupsTargetInListTargets(t, fetchedPolicy, listTargetsResp.Response)

		// ── Step 5: Delete policy (non-fatal) ─────────────────────────
		deletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)
	}, entragroups.ServiceConfig, groupaccess.ServiceConfig)
}
