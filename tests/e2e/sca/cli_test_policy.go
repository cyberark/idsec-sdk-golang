//go:build (e2e && sca) || e2e

package sca

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
	policycloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess"
	groupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess/models"
	scacloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

func buildPolicyName(prefix, principalName string) string {
	const maxPolicyNameLength = 200

	userDisplayName := strings.TrimSpace(principalName)
	if idx := strings.Index(userDisplayName, "@"); idx > 0 {
		userDisplayName = userDisplayName[:idx]
	}
	userDisplayName = sanitizePolicyNameSegment(userDisplayName)
	if userDisplayName == "" {
		userDisplayName = "user"
	}

	timestamp := time.Now().UTC().Format("20060102_150405")
	policyName := prefix + "_" + userDisplayName + "_" + timestamp
	if len(policyName) <= maxPolicyNameLength {
		return policyName
	}

	maxUserLen := maxPolicyNameLength - len(prefix) - len(timestamp) - 2
	if maxUserLen < 1 {
		return prefix + "_" + timestamp
	}
	if len(userDisplayName) > maxUserLen {
		userDisplayName = userDisplayName[:maxUserLen]
	}
	return prefix + "_" + userDisplayName + "_" + timestamp
}

func sanitizePolicyNameSegment(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(r)
		case r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func mustPolicyCloudAccessService(t *testing.T, ctx *framework.TestContext) *cloudaccess.IdsecPolicyCloudAccessService {
	t.Helper()

	policySvc, err := ctx.API.PolicyCloudaccess()
	require.NoError(t, err)
	return policySvc
}

func mustPolicyGroupAccessService(t *testing.T, ctx *framework.TestContext) *groupaccess.IdsecPolicyGroupAccessService {
	t.Helper()

	policySvc, err := ctx.API.PolicyGroupaccess()
	require.NoError(t, err)
	return policySvc
}

func createCloudAccessPolicy(
	t *testing.T,
	policySvc *cloudaccess.IdsecPolicyCloudAccessService,
	cfg cloudAccessListTargetsConfig,
	principal principalFields,
	target *scacloudaccessmodels.IdsecSCAEligibleTarget,
	policyNamePrefix string,
) string {
	t.Helper()

	policyName := buildPolicyName(policyNamePrefix, principal.Name)
	createdPolicy, err := policySvc.CreatePolicy(buildCloudAccessPolicy(cfg, policyName, principal, target))
	require.NoError(t, err)
	require.NotNil(t, createdPolicy)
	require.NotEmpty(t, createdPolicy.Metadata.PolicyID)
	createdPolicyID := createdPolicy.Metadata.PolicyID
	t.Logf("Policy created - ID: %s, Name: %s", createdPolicyID, policyName)
	return createdPolicyID
}

func createCloudAccessPaginationPolicies(
	t *testing.T,
	policySvc *cloudaccess.IdsecPolicyCloudAccessService,
	cfg cloudAccessListTargetsConfig,
	testCtx *k8sTestContext,
	principal principalFields,
) []string {
	t.Helper()

	if len(testCtx.Targets) < 2 {
		t.Logf("%s has %d configured target(s); using existing live eligible targets for pagination validation",
			cfg.configBlockKey, len(testCtx.Targets))
		return nil
	}

	createdPolicyIDs := make([]string, 0, 2)
	for i, targetCfg := range testCtx.Targets[:2] {
		target := buildCloudAccessEligibleTargetFromConfig(targetCfg)
		policyID := createCloudAccessPolicy(
			t,
			policySvc,
			cfg,
			principal,
			target,
			fmt.Sprintf("%s_%d", cfg.paginationPolicyNamePrefix, i+1),
		)
		createdPolicyIDs = append(createdPolicyIDs, policyID)
	}
	return createdPolicyIDs
}

func getCloudAccessPolicy(
	t *testing.T,
	policySvc *cloudaccess.IdsecPolicyCloudAccessService,
	policyID string,
) *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy {
	t.Helper()

	fetchedPolicy, err := policySvc.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: policyID,
	})
	require.NoError(t, err)
	require.NotNil(t, fetchedPolicy)
	requireFetchedPolicyActive(t, policyID, fetchedPolicy.Metadata)
	return fetchedPolicy
}

func createGroupAccessPolicy(
	t *testing.T,
	policySvc *groupaccess.IdsecPolicyGroupAccessService,
	principal principalFields,
	target groupaccessmodels.IdsecPolicyGroupAccessTargetItem,
	policyNamePrefix string,
) string {
	t.Helper()

	policyName := buildPolicyName(policyNamePrefix, principal.Name)
	createdPolicy, err := policySvc.CreatePolicy(buildAzureGroupAccessPolicyFromBodyTemplate(
		policyName,
		principal.ID,
		principal.Name,
		principal.SourceDirName,
		principal.SourceDirID,
		target,
	))
	require.NoError(t, err)
	require.NotNil(t, createdPolicy)
	require.NotEmpty(t, createdPolicy.Metadata.PolicyID)
	createdPolicyID := createdPolicy.Metadata.PolicyID
	t.Logf("Policy created - ID: %s, Name: %s", createdPolicyID, policyName)
	return createdPolicyID
}

func createGroupAccessPaginationPolicies(
	t *testing.T,
	policySvc *groupaccess.IdsecPolicyGroupAccessService,
	testCtx *k8sTestContext,
	principal principalFields,
) []string {
	t.Helper()

	if len(testCtx.Targets) < 2 {
		t.Logf("azure_groupaccess has %d configured target(s); using existing live eligible groups for pagination validation",
			len(testCtx.Targets))
		return nil
	}

	createdPolicyIDs := make([]string, 0, 2)
	for i, targetCfg := range testCtx.Targets[:2] {
		target := buildGroupAccessTargetFromConfig(targetCfg)
		policyID := createGroupAccessPolicy(
			t,
			policySvc,
			principal,
			target,
			fmt.Sprintf("sca_cli_groupaccess_azure_pagination_e2e_%d", i+1),
		)
		createdPolicyIDs = append(createdPolicyIDs, policyID)
	}
	return createdPolicyIDs
}

func getGroupAccessPolicy(
	t *testing.T,
	policySvc *groupaccess.IdsecPolicyGroupAccessService,
	policyID string,
) *groupaccessmodels.IdsecPolicyGroupAccessPolicy {
	t.Helper()

	fetchedPolicy, err := policySvc.Policy(&policycommonmodels.IdsecPolicyGetPolicyRequest{
		PolicyID: policyID,
	})
	require.NoError(t, err)
	require.NotNil(t, fetchedPolicy)
	requireFetchedPolicyActive(t, policyID, fetchedPolicy.Metadata)
	return fetchedPolicy
}

func createK8sPolicy(
	t *testing.T,
	policySvc *cloudaccess.IdsecPolicyCloudAccessService,
	cfg k8sListTargetsConfig,
	principal principalFields,
	target k8sTargetConfig,
	policyNamePrefix string,
) string {
	t.Helper()

	policyName := buildPolicyName(policyNamePrefix, principal.Name)
	createdPolicy, err := policySvc.CreatePolicy(buildK8sClusterPolicy(cfg, policyName, principal, target))
	require.NoError(t, err)
	require.NotNil(t, createdPolicy)
	require.NotEmpty(t, createdPolicy.Metadata.PolicyID)
	createdPolicyID := createdPolicy.Metadata.PolicyID
	t.Logf("Policy created - ID: %s, Name: %s", createdPolicyID, policyName)
	return createdPolicyID
}

func createK8sPaginationPolicies(
	t *testing.T,
	policySvc *cloudaccess.IdsecPolicyCloudAccessService,
	cfg k8sListTargetsConfig,
	testCtx *k8sTestContext,
	principal principalFields,
) []string {
	t.Helper()

	if len(testCtx.Targets) < 2 {
		t.Logf("%s has %d configured target(s); using existing live eligible clusters for pagination validation",
			cfg.configBlockKey, len(testCtx.Targets))
		return nil
	}

	createdPolicyIDs := make([]string, 0, 2)
	for i, targetCfg := range testCtx.Targets[:2] {
		target := cfg.buildTarget(targetCfg)
		policyID := createK8sPolicy(
			t,
			policySvc,
			cfg,
			principal,
			target,
			fmt.Sprintf("%s_%d", cfg.paginationPolicyNamePrefix, i+1),
		)
		createdPolicyIDs = append(createdPolicyIDs, policyID)
	}
	return createdPolicyIDs
}

func buildCloudAccessPolicy(
	cfg cloudAccessListTargetsConfig,
	policyName string,
	principal principalFields,
	target *scacloudaccessmodels.IdsecSCAEligibleTarget,
) *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy {
	return buildCloudAccessPolicyFromBodyTemplate(
		cfg.csp,
		policyName,
		principal.ID,
		principal.Name,
		principal.SourceDirName,
		principal.SourceDirID,
		target,
	)
}

func buildK8sClusterPolicy(
	cfg k8sListTargetsConfig,
	policyName string,
	principal principalFields,
	target k8sTargetConfig,
) *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy {
	return buildCloudAccessPolicyFromBodyTemplate(
		cfg.csp,
		policyName,
		principal.ID,
		principal.Name,
		principal.SourceDirName,
		principal.SourceDirID,
		target.PolicyTarget,
		withK8sClusterCloudAccessBuild(cfg.csp, target.PolicyTarget, target.Scope, target.ClusterID, target.FQDN),
	)
}

func validateAzureK8sFetchedPolicy(
	t *testing.T,
	fetchedPolicy *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy,
	target k8sTargetConfig,
) {
	t.Helper()

	require.Equal(t, []int{0, 1, 2, 3, 4, 5, 6}, fetchedPolicy.Conditions.AccessWindow.DaysOfTheWeek,
		"GetPolicy: access window days should match the Azure k8s payload")
	require.Equal(t, 1, fetchedPolicy.Conditions.MaxSessionDuration, "GetPolicy: max session duration should match the Azure k8s payload")
	require.Len(t, fetchedPolicy.Targets.AzureTargets, 1, "GetPolicy: expected exactly one azure k8s target")

	fetchedTarget := fetchedPolicy.Targets.AzureTargets[0]
	require.Equal(t, target.PolicyTarget.RoleInfo.ID, strings.TrimSpace(fetchedTarget.RoleID), "GetPolicy: role ID mismatch")
	require.Equal(t, target.PolicyTarget.RoleInfo.Name, strings.TrimSpace(fetchedTarget.RoleName), "GetPolicy: role name mismatch")
	require.Equal(t, target.PolicyTarget.WorkspaceID, strings.TrimSpace(fetchedTarget.WorkspaceID), "GetPolicy: workspace ID mismatch")
	require.Equal(t, target.PolicyTarget.WorkspaceName, strings.TrimSpace(fetchedTarget.WorkspaceName), "GetPolicy: workspace name mismatch")
	require.Equal(t, target.PolicyTarget.OrganizationID, strings.TrimSpace(fetchedTarget.OrgID), "GetPolicy: org ID mismatch")
	require.Equal(t, normalizeAzureWorkspaceType(target.PolicyTarget.WorkspaceType), strings.TrimSpace(fetchedTarget.WorkspaceType),
		"GetPolicy: workspace type mismatch")
	t.Log("Policy validated via GetPolicy")
}

func requireFetchedPolicyActive(
	t *testing.T,
	createdPolicyID string,
	metadata policycommonmodels.IdsecPolicyMetadata,
) {
	t.Helper()
	require.Equal(t, createdPolicyID, metadata.PolicyID, "GetPolicy: policy ID mismatch")
	require.NotEmpty(t, metadata.Name, "GetPolicy: name should not be empty")
	require.Equal(t, "Active", strings.TrimSpace(metadata.Status.Status), "GetPolicy: status should be Active")
	t.Log("Policy validated via GetPolicy")
}

func deletePolicyBestEffort(t *testing.T, policyID string, deleteFn func(*policycommonmodels.IdsecPolicyDeletePolicyRequest) error) {
	t.Helper()

	err := deleteFn(&policycommonmodels.IdsecPolicyDeletePolicyRequest{
		PolicyID: policyID,
	})
	if err != nil {
		t.Logf("WARNING: policy delete failed (non-fatal): %v", err)
	} else {
		t.Logf("Policy deleted — ID: %s", policyID)
	}
}

func buildAzureGroupAccessPolicyFromBodyTemplate(
	policyName string,
	policyPrincipalID string,
	policyPrincipalName string,
	sourceDirectoryName string,
	sourceDirectoryID string,
	target groupaccessmodels.IdsecPolicyGroupAccessTargetItem,
) *groupaccessmodels.IdsecPolicyGroupAccessPolicy {
	// Keep the Group Access policy body aligned with the cloudaccess E2E flow:
	// one principal, one target, recurring access window, and short session duration.
	return &groupaccessmodels.IdsecPolicyGroupAccessPolicy{
		IdsecPolicyCommonAccessPolicy: policycommonmodels.IdsecPolicyCommonAccessPolicy{
			Metadata: policycommonmodels.IdsecPolicyMetadata{
				Name:        policyName,
				Description: "",
				Status: policycommonmodels.IdsecPolicyStatus{
					Status: policycommonmodels.StatusTypeValidating,
				},
				TimeFrame: policycommonmodels.IdsecPolicyTimeFrame{
					FromTime: "",
					ToTime:   "",
				},
				PolicyEntitlement: policycommonmodels.IdsecPolicyEntitlement{
					TargetCategory: commonmodels.CategoryTypeGroupAccess,
					LocationType:   "Azure",
					PolicyType:     policycommonmodels.PolicyTypeRecurring,
				},
				PolicyTags: []string{},
				TimeZone:   "Asia/Calcutta",
			},
			Principals: []policycommonmodels.IdsecPolicyPrincipal{
				{
					ID:                  policyPrincipalID,
					Name:                policyPrincipalName,
					SourceDirectoryName: sourceDirectoryName,
					SourceDirectoryID:   sourceDirectoryID,
					Type:                policycommonmodels.PrincipalTypeUser,
				},
			},
			DelegationClassification: policycommonmodels.DelegationClassificationUnrestricted,
		},
		Conditions: policycommonmodels.IdsecPolicyConditions{
			AccessWindow: policycommonmodels.IdsecPolicyTimeCondition{
				DaysOfTheWeek: []int{0, 1, 2, 3, 4, 5, 6},
				FromHour:      "",
				ToHour:        "",
			},
			MaxSessionDuration: 1,
		},
		Targets: groupaccessmodels.IdsecPolicyGroupAccessTarget{
			Targets: []groupaccessmodels.IdsecPolicyGroupAccessTargetItem{
				{
					GroupID:     target.GroupID,
					DirectoryID: target.DirectoryID,
				},
			},
		},
	}
}

type cloudAccessPolicyBuildOption func(*cloudAccessPolicyBuildConfig)

type cloudAccessPolicyBuildConfig struct {
	targetCategory string
	policyTags     []string
	conditions     policycommonmodels.IdsecPolicyConditions
	targets        policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleTarget
}

// buildCloudAccessPolicyFromBodyTemplate builds a cloud access policy for either
// "AZURE" or "AWS" based on the csp parameter.
func buildCloudAccessPolicyFromBodyTemplate(
	csp string,
	policyName string,
	policyPrincipalID string,
	policyPrincipalName string,
	sourceDirectoryName string,
	sourceDirectoryID string,
	target *scacloudaccessmodels.IdsecSCAEligibleTarget,
	opts ...cloudAccessPolicyBuildOption,
) *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy {
	locationType := "Azure"
	config := cloudAccessPolicyBuildConfig{
		targetCategory: commonmodels.CategoryTypeCloudConsole,
		policyTags:     []string{},
		conditions: policycommonmodels.IdsecPolicyConditions{
			AccessWindow: policycommonmodels.IdsecPolicyTimeCondition{
				DaysOfTheWeek: []int{0, 1, 2, 3, 4, 5, 6},
				FromHour:      "",
				ToHour:        "",
			},
			MaxSessionDuration: 1,
		},
		targets: policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleTarget{
			AzureTargets: []policycloudaccessmodels.IdsecPolicyCloudAccessAzureTarget{
				{
					IdsecPolicyCloudAccessTarget: policycloudaccessmodels.IdsecPolicyCloudAccessTarget{
						RoleID:      target.RoleInfo.ID,
						WorkspaceID: target.WorkspaceID,
					},
					OrgID:         target.OrganizationID,
					WorkspaceType: normalizeAzureWorkspaceType(target.WorkspaceType),
				},
			},
		},
	}

	if strings.EqualFold(strings.TrimSpace(csp), "AWS") {
		locationType = "AWS"
		config.policyTags = []string{"pre_defined"}
		config.targets = policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleTarget{
			AwsAccountTargets: []policycloudaccessmodels.IdsecPolicyCloudAccessAWSAccountTarget{
				{
					IdsecPolicyCloudAccessTarget: policycloudaccessmodels.IdsecPolicyCloudAccessTarget{
						RoleID:      target.RoleInfo.ID,
						WorkspaceID: target.WorkspaceID,
					},
				},
			},
		}
	}

	for _, opt := range opts {
		opt(&config)
	}

	return &policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy{
		IdsecPolicyCommonAccessPolicy: policycommonmodels.IdsecPolicyCommonAccessPolicy{
			Metadata: policycommonmodels.IdsecPolicyMetadata{
				Name:        policyName,
				Description: "",
				Status: policycommonmodels.IdsecPolicyStatus{
					Status: policycommonmodels.StatusTypeValidating,
				},
				TimeFrame: policycommonmodels.IdsecPolicyTimeFrame{
					FromTime: "",
					ToTime:   "",
				},
				PolicyEntitlement: policycommonmodels.IdsecPolicyEntitlement{
					TargetCategory: config.targetCategory,
					LocationType:   locationType,
					PolicyType:     policycommonmodels.PolicyTypeRecurring,
				},
				PolicyTags: config.policyTags,
				TimeZone:   "Asia/Calcutta",
			},
			Principals: []policycommonmodels.IdsecPolicyPrincipal{
				{
					ID:                  policyPrincipalID,
					Name:                policyPrincipalName,
					SourceDirectoryName: sourceDirectoryName,
					SourceDirectoryID:   sourceDirectoryID,
					Type:                policycommonmodels.PrincipalTypeUser,
				},
			},
			DelegationClassification: policycommonmodels.DelegationClassificationUnrestricted,
		},
		Conditions: config.conditions,
		Targets:    config.targets,
	}
}

func withK8sClusterCloudAccessBuild(
	csp string,
	target *scacloudaccessmodels.IdsecSCAEligibleTarget,
	scope string,
	clusterID string,
	fqdn string,
) cloudAccessPolicyBuildOption {
	return func(config *cloudAccessPolicyBuildConfig) {
		config.policyTags = []string{}

		if strings.EqualFold(strings.TrimSpace(csp), "AZURE") {
			config.conditions = policycommonmodels.IdsecPolicyConditions{
				AccessWindow: policycommonmodels.IdsecPolicyTimeCondition{
					DaysOfTheWeek: []int{0, 1, 2, 3, 4, 5, 6},
					FromHour:      "",
					ToHour:        "",
				},
				MaxSessionDuration: 1,
			}
			config.targets = policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleTarget{
				AzureTargets: []policycloudaccessmodels.IdsecPolicyCloudAccessAzureTarget{
					{
						IdsecPolicyCloudAccessTarget: policycloudaccessmodels.IdsecPolicyCloudAccessTarget{
							RoleID:        target.RoleInfo.ID,
							WorkspaceID:   target.WorkspaceID,
							RoleName:      target.RoleInfo.Name,
							WorkspaceName: target.WorkspaceName,
						},
						OrgID:         target.OrganizationID,
						WorkspaceType: normalizeAzureWorkspaceType(target.WorkspaceType),
					},
				},
			}
			return
		}

		config.conditions = policycommonmodels.IdsecPolicyConditions{
			AccessWindow: policycommonmodels.IdsecPolicyTimeCondition{
				DaysOfTheWeek: []int{1, 2, 3, 4, 5, 6, 0},
				FromHour:      "",
				ToHour:        "",
			},
			MaxSessionDuration: 2,
		}
		config.targets = policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleTarget{
			AwsAccountTargets: []policycloudaccessmodels.IdsecPolicyCloudAccessAWSAccountTarget{
				{
					IdsecPolicyCloudAccessTarget: policycloudaccessmodels.IdsecPolicyCloudAccessTarget{
						RoleID:        target.RoleInfo.ID,
						WorkspaceID:   target.WorkspaceID,
						RoleName:      target.RoleInfo.Name,
						WorkspaceName: target.WorkspaceName,
					},
				},
			},
		}
	}
}
