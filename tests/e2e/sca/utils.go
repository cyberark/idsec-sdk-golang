//go:build (e2e && sca) || e2e

package sca

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	policycloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	groupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess/models"
	cloudconsoleservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudconsole"
	cloudconsolemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudconsole/models"
	entragroupsservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/entragroups"
	entragroupsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/entragroups/models"
)

// ---------------------------------------------------------------------------
// Policy name builder
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Policy active poller
// ---------------------------------------------------------------------------

// waitForPolicyActive polls fetchStatus until the returned status is "Active",
// or fails after maxAttempts. Works for any policy type — the caller extracts
// the status string from its own typed GetPolicy response.
func waitForPolicyActive(
	t *testing.T,
	policyID string,
	fetchStatus func() (string, error),
) error {
	t.Helper()

	const (
		maxAttempts  = 6
		sleepBetween = 5 * time.Second
	)

	var lastStatus string

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		status, err := fetchStatus()
		if err == nil {
			status = strings.TrimSpace(status)
			switch strings.ToLower(status) {
			case "active":
				return nil
			case "failed", "error", "invalid", "rejected", "denied":
				return fmt.Errorf("policy %s entered terminal failure status %q", policyID, status)
			default:
				lastStatus = status
			}
		}

		if attempt == maxAttempts {
			if err != nil {
				return fmt.Errorf("policy %s did not become active after %d attempts: %w", policyID, maxAttempts, err)
			}
			return fmt.Errorf("policy %s did not become active after %d attempts (last status: %q)", policyID, maxAttempts, lastStatus)
		}

		time.Sleep(sleepBetween)
	}

	return fmt.Errorf("policy %s did not become active", policyID)
}

func buildPrincipalISPAuthenticator(
	t *testing.T,
	authCfg map[string]interface{},
	principalCfg map[string]interface{},
) (*auth.IdsecISPAuth, error) {
	t.Helper()

	// Re-authenticate as the target principal so ListTargets reflects the same
	// user context that the policy is created for.
	// Credentials must be provided via env vars — never committed in config.
	principalUsername := strings.TrimSpace(os.Getenv("IDSEC_E2E_SCA_PRINCIPAL_USERNAME"))
	if principalUsername == "" {
		principalUsername = strings.TrimSpace(strVal(principalCfg, "principal_name"))
	}
	principalSecret := strings.TrimSpace(os.Getenv("IDSEC_E2E_SCA_PRINCIPAL_SECRET"))
	t.Logf("Principal auth: using principal-specific secret for %s", principalUsername)

	require.NotEmpty(t, principalUsername, "principal_name is required for principal-auth ListTargets")
	require.NotEmpty(t, principalSecret, "principal secret is required for principal-auth ListTargets")

	authMethod := authmodels.IdentityServiceUser
	if strings.EqualFold(strings.TrimSpace(strVal(authCfg, "method")), "identity") {
		authMethod = authmodels.Identity
	}

	var authMethodSettings authmodels.IdsecAuthMethodSettings
	switch authMethod {
	case authmodels.Identity:
		authMethodSettings = &authmodels.IdentityIdsecAuthMethodSettings{
			IdentityURL:             strVal(authCfg, "identity_url"),
			IdentityTenantSubdomain: strVal(authCfg, "identity_tenant_subdomain"),
			IdentityMFAInteractive:  false,
		}
	default:
		authMethodSettings = &authmodels.IdentityServiceUserIdsecAuthMethodSettings{
			IdentityURL:                      strVal(authCfg, "identity_url"),
			IdentityTenantSubdomain:          strVal(authCfg, "identity_tenant_subdomain"),
			IdentityAuthorizationApplication: "",
		}
	}

	authenticator := auth.NewIdsecISPAuth(false)
	ispAuthenticator := authenticator.(*auth.IdsecISPAuth)
	authProfile := &authmodels.IdsecAuthProfile{
		Username:           principalUsername,
		AuthMethod:         authMethod,
		AuthMethodSettings: authMethodSettings,
	}
	secret := &authmodels.IdsecSecret{Secret: principalSecret}

	_, err := ispAuthenticator.Authenticate(nil, authProfile, secret, false, false)
	if err != nil {
		return nil, fmt.Errorf("principal ISP authentication failed for %s: %w", principalUsername, err)
	}

	t.Logf("Principal auth successful: %s", principalUsername)
	return ispAuthenticator, nil
}

func buildPrincipalCloudConsoleService(
	t *testing.T,
	authCfg map[string]interface{},
	principalCfg map[string]interface{},
) (*cloudconsoleservice.IdsecSCACloudConsoleService, error) {
	t.Helper()

	authenticator, err := buildPrincipalISPAuthenticator(t, authCfg, principalCfg)
	if err != nil {
		return nil, err
	}

	t.Logf("Principal auth successful for ListTargets: %s", strings.TrimSpace(strVal(principalCfg, "principal_name")))
	return cloudconsoleservice.NewIdsecSCACloudConsoleService(authenticator)
}

func buildPrincipalEntraGroupsService(
	t *testing.T,
	authCfg map[string]interface{},
	principalCfg map[string]interface{},
) (*entragroupsservice.IdsecSCAEntraGroupsService, error) {
	t.Helper()

	authenticator, err := buildPrincipalISPAuthenticator(t, authCfg, principalCfg)
	if err != nil {
		return nil, err
	}

	t.Logf("Principal auth successful for Entra Groups ListTargets: %s", strings.TrimSpace(strVal(principalCfg, "principal_name")))
	return entragroupsservice.NewIdsecSCAEntraGroupsService(authenticator)
}

func verifyCloudConsoleTargetInListTargets(
	t *testing.T,
	fetchedPolicy *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy,
	listResponse []cloudconsolemodels.IdsecSCAEligibleTarget,
) {
	t.Helper()

	require.NotNil(t, fetchedPolicy, "GetPolicy response must not be nil")
	require.Len(t, fetchedPolicy.Targets.AzureTargets, 1, "GetPolicy: expected exactly one azure target")

	expectedTarget := fetchedPolicy.Targets.AzureTargets[0]
	expectedRoleID := strings.TrimSpace(expectedTarget.RoleID)
	expectedWorkspaceID := strings.TrimSpace(expectedTarget.WorkspaceID)
	expectedOrganizationID := strings.TrimSpace(expectedTarget.OrgID)
	expectedWorkspaceType := normalizeAzureWorkspaceType(expectedTarget.WorkspaceType)
	t.Logf("Expected target from GetPolicy: roleId=%s workspaceId=%s orgId=%s workspaceType=%s",
		expectedRoleID, expectedWorkspaceID, expectedOrganizationID, expectedWorkspaceType)

	if len(listResponse) == 0 {
		t.Logf("ListTargets returned 0 targets")
	}
	require.NotEmpty(t, listResponse, "ListTargets: response should not be empty")

	for _, actualTarget := range listResponse {
		actualRoleID := strings.TrimSpace(actualTarget.RoleInfo.ID)
		actualWorkspaceID := strings.TrimSpace(actualTarget.WorkspaceID)
		actualOrganizationID := strings.TrimSpace(actualTarget.OrganizationID)
		actualWorkspaceType := normalizeAzureWorkspaceType(actualTarget.WorkspaceType)
		if actualRoleID == expectedRoleID &&
			actualWorkspaceID == expectedWorkspaceID &&
			actualOrganizationID == expectedOrganizationID &&
			actualWorkspaceType == expectedWorkspaceType {
			t.Logf("Policy target validated via ListTargets: roleId=%s workspaceId=%s orgId=%s workspaceType=%s",
				actualRoleID, actualWorkspaceID, actualOrganizationID, actualWorkspaceType)
			return
		}
	}

	require.Failf(t, "ListTargets target mismatch",
		"Expected target from GetPolicy not found in ListTargets response: roleId=%s workspaceId=%s orgId=%s workspaceType=%s",
		expectedRoleID, expectedWorkspaceID, expectedOrganizationID, expectedWorkspaceType)
}

func verifyEntraGroupsTargetInListTargets(
	t *testing.T,
	fetchedPolicy *groupaccessmodels.IdsecPolicyGroupAccessPolicy,
	listResponse []entragroupsmodels.IdsecSCAGroupsEligibleTarget,
) {
	t.Helper()

	require.NotNil(t, fetchedPolicy, "GetPolicy response must not be nil")
	require.Len(t, fetchedPolicy.Targets.Targets, 1, "GetPolicy: expected exactly one Entra group target")

	// The policy target and eligibility response use the same group/directory keys,
	// so a direct field comparison is enough for this E2E validation.
	expectedTarget := fetchedPolicy.Targets.Targets[0]
	expectedGroupID := strings.TrimSpace(expectedTarget.GroupID)
	expectedDirectoryID := strings.TrimSpace(expectedTarget.DirectoryID)
	expectedGroupName := strings.TrimSpace(expectedTarget.GroupName)
	t.Logf("Expected target from GetPolicy: groupId=%s directoryId=%s groupName=%s",
		expectedGroupID, expectedDirectoryID, expectedGroupName)

	if len(listResponse) == 0 {
		t.Logf("ListTargets returned 0 groups")
	}
	require.NotEmpty(t, listResponse, "ListTargets: response should not be empty")

	for _, actualTarget := range listResponse {
		actualGroupID := strings.TrimSpace(actualTarget.GroupID)
		actualDirectoryID := strings.TrimSpace(actualTarget.DirectoryID)
		actualGroupName := strings.TrimSpace(actualTarget.GroupName)
		if actualGroupID == expectedGroupID && actualDirectoryID == expectedDirectoryID {
			if expectedGroupName != "" {
				require.Equal(t, expectedGroupName, actualGroupName, "ListTargets: group name mismatch")
			}
			t.Logf("Policy target validated via ListTargets: groupId=%s directoryId=%s groupName=%s",
				actualGroupID, actualDirectoryID, actualGroupName)
			return
		}
	}

	require.Failf(t, "ListTargets target mismatch",
		"Expected target from GetPolicy not found in ListTargets response: groupId=%s directoryId=%s groupName=%s",
		expectedGroupID, expectedDirectoryID, expectedGroupName)
}

// ---------------------------------------------------------------------------
// Non-fatal policy cleanup
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Cloud Console policy builder
// ---------------------------------------------------------------------------

func buildAzurePolicyFromBodyTemplate(
	policyName string,
	policyPrincipalID string,
	policyPrincipalName string,
	sourceDirectoryName string,
	sourceDirectoryID string,
	target *cloudconsolemodels.IdsecSCAEligibleTarget,
) *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy {
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
					TargetCategory: commonmodels.CategoryTypeCloudConsole,
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
		Targets: policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleTarget{
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
}

func buildAzureEntraGroupsPolicyFromBodyTemplate(
	policyName string,
	policyPrincipalID string,
	policyPrincipalName string,
	sourceDirectoryName string,
	sourceDirectoryID string,
	target groupaccessmodels.IdsecPolicyGroupAccessTargetItem,
) *groupaccessmodels.IdsecPolicyGroupAccessPolicy {
	// Keep the Entra Groups policy body aligned with the cloud-console E2E flow:
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

// ---------------------------------------------------------------------------
// Workspace type normalizer
// ---------------------------------------------------------------------------

func normalizeAzureWorkspaceType(workspaceType string) string {
	normalized := strings.ToUpper(strings.TrimSpace(workspaceType))
	switch normalized {
	case "DIRECTORY":
		return policycloudaccessmodels.AzureWSTypeDirectory
	case "SUBSCRIPTION":
		return policycloudaccessmodels.AzureWSTypeSubscription
	case "RESOURCE_GROUP", "RESOURCE GROUP":
		return policycloudaccessmodels.AzureWSTypeResourceGroup
	case "RESOURCE":
		return policycloudaccessmodels.AzureWSTypeResource
	case "MANAGEMENT_GROUP", "MANAGEMENT GROUP":
		return policycloudaccessmodels.AzureWSTypeManagementGroup
	default:
		return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(workspaceType), " ", "_"))
	}
}
