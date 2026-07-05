//go:build (e2e && sca) || e2e

package sca

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	policycloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
	groupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess/models"
	scacloudaccesssvc "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess"
	scacloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess/models"
	scagroupaccesssvc "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/groupaccess"
	scagroupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/groupaccess/models"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
	"gopkg.in/yaml.v3"
)

func logJSON(t *testing.T, label string, value interface{}) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Logf("%s: %+v", label, value)
		return
	}
	t.Logf("%s:\n%s", label, string(data))
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
	t.Log("Principal auth: using principal-specific secret for configured principal user")

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
		return nil, fmt.Errorf("principal ISP authentication failed for configured principal user: %w", err)
	}

	t.Log("Principal auth successful for configured principal user")
	return ispAuthenticator, nil
}

func buildPrincipalCloudAccessService(
	t *testing.T,
	authCfg map[string]interface{},
	principalCfg map[string]interface{},
) (*scacloudaccesssvc.IdsecSCACloudAccessService, error) {
	t.Helper()

	authenticator, err := buildPrincipalISPAuthenticator(t, authCfg, principalCfg)
	if err != nil {
		return nil, err
	}

	t.Log("Principal auth successful for configured principal user ListTargets")
	return scacloudaccesssvc.NewIdsecSCACloudAccessService(authenticator)
}

func buildPrincipalGroupAccessService(
	t *testing.T,
	authCfg map[string]interface{},
	principalCfg map[string]interface{},
) (*scagroupaccesssvc.IdsecSCAGroupAccessService, error) {
	t.Helper()

	authenticator, err := buildPrincipalISPAuthenticator(t, authCfg, principalCfg)
	if err != nil {
		return nil, err
	}

	t.Log("Principal auth successful for configured principal user Group Access ListTargets")
	return scagroupaccesssvc.NewIdsecSCAGroupAccessService(authenticator)
}

func buildPrincipalK8sService(
	t *testing.T,
	authCfg map[string]interface{},
	principalCfg map[string]interface{},
) (*k8sservice.IdsecSCAK8sService, error) {
	t.Helper()

	authenticator, err := buildPrincipalISPAuthenticator(t, authCfg, principalCfg)
	if err != nil {
		return nil, err
	}

	t.Log("Principal auth successful for configured principal user K8s ListTargets")
	return k8sservice.NewIdsecSCAK8sService(authenticator)
}

func loadListTargetsTestContext(t *testing.T, configBlockKey string) *K8sTestContext {
	t.Helper()

	cfg := LoadSCATestConfig(t)
	block := cspBlock(cfg, configBlockKey)
	authCfg := cspBlock(cfg, "auth")
	require.NotNil(t, block, "%s block is required in JSON config", configBlockKey)
	require.NotNil(t, authCfg, "auth block is required in JSON config")

	principal := principalBlock(block)
	require.NotNil(t, principal, "%s.principal block is required", configBlockKey)

	return &K8sTestContext{
		AuthBlock:      authCfg,
		PrincipalBlock: principal,
		Targets:        configTargets(block),
	}
}

func buildPrincipalFields(principalCfg map[string]interface{}) PrincipalFields {
	return PrincipalFields{
		ID:            strVal(principalCfg, "principal_id"),
		Name:          strVal(principalCfg, "principal_name"),
		SourceDirName: strVal(principalCfg, "source_directory_name"),
		SourceDirID:   strVal(principalCfg, "source_directory_id"),
	}
}

func buildCloudAccessEligibleTargetFromConfig(targetCfg map[string]interface{}) *scacloudaccessmodels.IdsecSCAEligibleTarget {
	return &scacloudaccessmodels.IdsecSCAEligibleTarget{
		WorkspaceID:    strVal(targetCfg, "workspaceId"),
		WorkspaceName:  strVal(targetCfg, "workspaceName"),
		OrganizationID: strVal(targetCfg, "orgId"),
		WorkspaceType:  strVal(targetCfg, "workspaceType"),
		RoleInfo: scacloudaccessmodels.IdsecSCARoleInfo{
			ID:   strVal(targetCfg, "roleId"),
			Name: strVal(targetCfg, "roleName"),
		},
	}
}

func buildGroupAccessTargetFromConfig(targetCfg map[string]interface{}) groupaccessmodels.IdsecPolicyGroupAccessTargetItem {
	return groupaccessmodels.IdsecPolicyGroupAccessTargetItem{
		GroupID:     strVal(targetCfg, "groupId"),
		DirectoryID: strVal(targetCfg, "directoryId"),
		GroupName:   strVal(targetCfg, "groupName"),
	}
}

func buildAWSK8sTargetFromConfig(targetCfg map[string]interface{}) K8sTargetConfig {
	target := buildCloudAccessEligibleTargetFromConfig(targetCfg)
	return K8sTargetConfig{
		PolicyTarget: target,
		VerifyTarget: target,
		Scope:        strVal(targetCfg, "scope"),
		ClusterID:    strVal(targetCfg, "clusterId"),
		FQDN:         strVal(targetCfg, "fqdn"),
	}
}

func buildAzureK8sTargetFromConfig(targetCfg map[string]interface{}) K8sTargetConfig {
	policyTarget := buildCloudAccessEligibleTargetFromConfig(targetCfg)
	verifyTarget := buildCloudAccessEligibleTargetFromConfig(targetCfg)
	verifyTarget.WorkspaceType = ""

	return K8sTargetConfig{
		PolicyTarget: policyTarget,
		VerifyTarget: verifyTarget,
		Scope:        strVal(targetCfg, "scope"),
		ClusterID:    strVal(targetCfg, "clusterId"),
		FQDN:         strVal(targetCfg, "fqdn"),
	}
}

func SetupCloudAccessListTargetsTest(t *testing.T, cfg CloudAccessListTargetsConfig, requireConfiguredTarget bool) *K8sTestContext {
	t.Helper()
	skipUnlessSupportedSCAEnv(t)

	testCtx := loadListTargetsTestContext(t, cfg.ConfigBlockKey)
	if requireConfiguredTarget {
		require.NotEmpty(t, testCtx.Targets, "%s.targets.targets array is required", cfg.ConfigBlockKey)
	}
	return testCtx
}

func CloudAccessPrincipalFromConfig(t *testing.T, testCtx *K8sTestContext) PrincipalFields {
	t.Helper()

	principal := buildPrincipalFields(testCtx.PrincipalBlock)
	t.Log("Using configured principal user from config")
	return principal
}

func CloudAccessTargetFromConfig(t *testing.T, testCtx *K8sTestContext, targetIndex int) *scacloudaccessmodels.IdsecSCAEligibleTarget {
	t.Helper()
	require.Greater(t, len(testCtx.Targets), targetIndex, "configured target index %d is required", targetIndex)

	target := buildCloudAccessEligibleTargetFromConfig(testCtx.Targets[targetIndex])
	t.Logf("Using target from config: workspaceId=%s workspaceName=%s roleId=%s roleName=%s orgId=%s workspaceType=%s",
		target.WorkspaceID, target.WorkspaceName, target.RoleInfo.ID, target.RoleInfo.Name, target.OrganizationID, target.WorkspaceType)
	return target
}

func MustPrincipalCloudAccessService(t *testing.T, testCtx *K8sTestContext) *scacloudaccesssvc.IdsecSCACloudAccessService {
	t.Helper()

	cloudAccessSvc, err := buildPrincipalCloudAccessService(t, testCtx.AuthBlock, testCtx.PrincipalBlock)
	require.NoError(t, err)
	return cloudAccessSvc
}

func ListCloudAccessTargets(
	t *testing.T,
	cloudAccessSvc *scacloudaccesssvc.IdsecSCACloudAccessService,
	csp string,
	workspaceID string,
	limit int,
) *scacloudaccessmodels.IdsecSCAListTargetsResponse {
	t.Helper()

	resp, err := cloudAccessSvc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:         csp,
		WorkspaceID: workspaceID,
		Limit:       limit,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func ListCloudAccessTargetsWithNextToken(
	t *testing.T,
	cloudAccessSvc *scacloudaccesssvc.IdsecSCACloudAccessService,
	cfg CloudAccessListTargetsConfig,
) (*scacloudaccessmodels.IdsecSCAListTargetsResponse, *scacloudaccessmodels.IdsecSCAListTargetsResponse) {
	t.Helper()

	page1, err := cloudAccessSvc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:   cfg.CSP,
		Limit: 1,
	})
	require.NoError(t, err)
	require.Len(t, page1.Response, 1, "expected exactly one cloudaccess target on the first page with limit=1")
	if page1.Total < 2 || strings.TrimSpace(page1.NextToken) == "" {
		t.Skipf("live CloudAccess ListTargets did not return a second page: total=%d nextToken=%q", page1.Total, page1.NextToken)
	}

	page2, err := cloudAccessSvc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:       cfg.CSP,
		Limit:     1,
		NextToken: page1.NextToken,
	})
	require.NoError(t, err)
	require.Len(t, page2.Response, 1, "expected exactly one cloudaccess target on the second page with limit=1")
	return page1, page2
}

func VerifyCloudAccessPagination(
	t *testing.T,
	page1 *scacloudaccessmodels.IdsecSCAListTargetsResponse,
	page2 *scacloudaccessmodels.IdsecSCAListTargetsResponse,
) {
	t.Helper()

	require.NotEqual(t, cloudAccessPaginationTargetKey(page1.Response[0]), cloudAccessPaginationTargetKey(page2.Response[0]),
		"expected pagination to return a different cloudaccess target on the second page")
	t.Logf("Pagination: page1=%d targets, page2=%d targets, nextToken=%q",
		len(page1.Response), len(page2.Response), page2.NextToken)
}

func VerifyCloudAccessFilteredTargets(
	t *testing.T,
	cfg CloudAccessListTargetsConfig,
	fetchedPolicy *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy,
	target *scacloudaccessmodels.IdsecSCAEligibleTarget,
	filteredResp *scacloudaccessmodels.IdsecSCAListTargetsResponse,
) {
	t.Helper()

	logJSON(t, "Actual CloudAccess ListTargets response", filteredResp)
	require.NotEmpty(t, filteredResp.Response, "Workspace-filtered CloudAccess ListTargets response should not be empty")
	cfg.VerifyTarget(t, fetchedPolicy, target, filteredResp.Response)
}

func RunAzureCloudAccessElevateTest(
	t *testing.T,
	ctx *framework.TestContext,
	testCtx *K8sTestContext,
	cfg CloudAccessListTargetsConfig,
	displayName string,
	policyNamePrefix string,
) {
	t.Helper()

	policySvc := MustPolicyCloudAccessService(t, ctx)
	principal := CloudAccessPrincipalFromConfig(t, testCtx)
	target := CloudAccessTargetFromConfig(t, testCtx, 0)
	createdPolicyID := CreateCloudAccessPolicy(t, policySvc, cfg, principal, target, policyNamePrefix)
	defer DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

	fetchedPolicy := GetCloudAccessPolicy(t, policySvc, createdPolicyID)

	cloudAccessSvc := MustPrincipalCloudAccessService(t, testCtx)
	filteredResp := ListCloudAccessTargets(t, cloudAccessSvc, cfg.CSP, target.WorkspaceID, 20)
	VerifyCloudAccessFilteredTargets(t, cfg, fetchedPolicy, target, filteredResp)

	t.Logf("ListTargets validation passed; attempting %s for principal %s", displayName, principal.Name)
	elevateResp, err := cloudAccessSvc.Elevate(&scacloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:            cfg.CSP,
		WorkspaceID:    target.WorkspaceID,
		RoleIDs:        target.RoleInfo.ID,
		OrganizationID: target.OrganizationID,
	})
	require.Nil(t, elevateResp)
	verifyAzureElevateFailsForNonEntraUser(t, err, "Azure CloudAccess elevation")
}

func ElevateCloudAccessTarget(
	t *testing.T,
	cloudAccessSvc *scacloudaccesssvc.IdsecSCACloudAccessService,
	cfg CloudAccessListTargetsConfig,
	target *scacloudaccessmodels.IdsecSCAEligibleTarget,
) *scacloudaccessmodels.IdsecSCACloudAccessElevateResponse {
	t.Helper()

	elevateResp, err := cloudAccessSvc.Elevate(&scacloudaccessmodels.IdsecSCACloudAccessElevateActionRequest{
		CSP:            cfg.CSP,
		WorkspaceID:    target.WorkspaceID,
		RoleIDs:        target.RoleInfo.ID,
		OrganizationID: target.OrganizationID,
	})
	require.NoError(t, err)
	require.NotNil(t, elevateResp)
	return elevateResp
}

func VerifyAWSCloudAccessElevate(
	t *testing.T,
	elevateResp *scacloudaccessmodels.IdsecSCACloudAccessElevateResponse,
	target *scacloudaccessmodels.IdsecSCAEligibleTarget,
) {
	t.Helper()

	require.Equal(t, AWSCloudAccessListTargetsConfig.CSP, strings.ToUpper(strings.TrimSpace(elevateResp.Response.CSP)))
	require.Len(t, elevateResp.Response.Results, 1, "expected one AWS elevate result")

	result := elevateResp.Response.Results[0]
	require.Equal(t, target.WorkspaceID, strings.TrimSpace(result.WorkspaceID), "Elevate: workspace ID mismatch")
	require.Equal(t, target.RoleInfo.ID, strings.TrimSpace(result.RoleID), "Elevate: role ID mismatch")
	require.Nil(t, result.ErrorInfo, "Elevate returned per-target error: %+v", result.ErrorInfo)
	require.NotEmpty(t, result.SessionID, "Elevate: expected session ID")
	require.NotEmpty(t, result.AccessCredentials, "Elevate: expected AWS access credentials")
	awsCreds := requireAWSAccessCredentials(t, result.AccessCredentials)
	verifyAWSAccessCredentialsIdentity(t, awsCreds, target)
}

func RunGroupAccessElevateTest(
	t *testing.T,
	ctx *framework.TestContext,
	testCtx *K8sTestContext,
	displayName string,
	policyNamePrefix string,
) {
	t.Helper()

	policySvc := MustPolicyGroupAccessService(t, ctx)
	principal := CloudAccessPrincipalFromConfig(t, testCtx)
	target := GroupAccessTargetFromConfig(t, testCtx, 0)
	createdPolicyID := CreateGroupAccessPolicy(t, policySvc, principal, target, policyNamePrefix)
	defer DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

	fetchedPolicy := GetGroupAccessPolicy(t, policySvc, createdPolicyID)
	groupAccessSvc := MustPrincipalGroupAccessService(t, testCtx)
	listResp := ListGroupAccessTargets(t, groupAccessSvc, 20)
	VerifyGroupAccessTargetInListTargets(t, fetchedPolicy, listResp.Response)

	t.Logf("ListTargets validation passed; attempting %s for principal %s", displayName, principal.Name)
	elevateResp, err := groupAccessSvc.Elevate(&scagroupaccessmodels.IdsecSCAGroupAccessElevateActionRequest{
		CSP:         "AZURE",
		DirectoryID: target.DirectoryID,
		Groups:      target.GroupID,
	})
	require.Nil(t, elevateResp)
	verifyAzureElevateFailsForNonEntraUser(t, err, "GroupAccess Azure elevation")
}

func verifyAzureElevateFailsForNonEntraUser(t *testing.T, err error, operation string) {
	t.Helper()

	require.Error(t, err, "%s should fail for a non-Entra ID federated user", operation)
	t.Logf("%s failed as expected for non-Entra ID federated user: %v", operation, err)
	errorMessage := err.Error()
	require.Contains(t, errorMessage, "500")
	require.Contains(t, strings.ToLower(errorMessage), "ca1040")
}

func SetupGroupAccessListTargetsTest(t *testing.T, requireConfiguredTarget bool) *K8sTestContext {
	t.Helper()
	skipUnlessSupportedSCAEnv(t)

	testCtx := loadListTargetsTestContext(t, "azure_groupaccess")
	if requireConfiguredTarget {
		require.NotEmpty(t, testCtx.Targets, "azure_groupaccess.targets.targets array is required")
	}
	return testCtx
}

func GroupAccessTargetFromConfig(t *testing.T, testCtx *K8sTestContext, targetIndex int) groupaccessmodels.IdsecPolicyGroupAccessTargetItem {
	t.Helper()
	require.Greater(t, len(testCtx.Targets), targetIndex, "configured group target index %d is required", targetIndex)

	target := buildGroupAccessTargetFromConfig(testCtx.Targets[targetIndex])
	t.Logf("Using group target from config: groupId=%s directoryId=%s groupName=%s",
		target.GroupID, target.DirectoryID, target.GroupName)
	return target
}

func MustPrincipalGroupAccessService(t *testing.T, testCtx *K8sTestContext) *scagroupaccesssvc.IdsecSCAGroupAccessService {
	t.Helper()

	groupAccessSvc, err := buildPrincipalGroupAccessService(t, testCtx.AuthBlock, testCtx.PrincipalBlock)
	require.NoError(t, err)
	return groupAccessSvc
}

func ListGroupAccessTargets(
	t *testing.T,
	groupAccessSvc *scagroupaccesssvc.IdsecSCAGroupAccessService,
	limit int,
) *scagroupaccessmodels.IdsecSCAListGroupTargetsResponse {
	t.Helper()

	resp, err := groupAccessSvc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:   "AZURE",
		Limit: limit,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func ListGroupAccessTargetsWithNextToken(
	t *testing.T,
	groupAccessSvc *scagroupaccesssvc.IdsecSCAGroupAccessService,
) (*scagroupaccessmodels.IdsecSCAListGroupTargetsResponse, *scagroupaccessmodels.IdsecSCAListGroupTargetsResponse) {
	t.Helper()

	page1 := ListGroupAccessTargets(t, groupAccessSvc, 1)
	require.Len(t, page1.Response, 1, "expected exactly one group target on the first page with limit=1")
	if page1.Total < 2 || strings.TrimSpace(page1.NextToken) == "" {
		t.Skipf("live GroupAccess ListTargets did not return a second page: total=%d nextToken=%q", page1.Total, page1.NextToken)
	}

	page2, err := groupAccessSvc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{
		CSP:       "AZURE",
		Limit:     1,
		NextToken: page1.NextToken,
	})
	require.NoError(t, err)
	require.Len(t, page2.Response, 1, "expected exactly one group target on the second page with limit=1")
	return page1, page2
}

func VerifyGroupAccessPagination(
	t *testing.T,
	page1 *scagroupaccessmodels.IdsecSCAListGroupTargetsResponse,
	page2 *scagroupaccessmodels.IdsecSCAListGroupTargetsResponse,
) {
	t.Helper()

	require.NotEqual(t, groupAccessPaginationTargetKey(page1.Response[0]), groupAccessPaginationTargetKey(page2.Response[0]),
		"expected pagination to return a different group target on the second page")
	t.Logf("Pagination: page1=%d groups, page2=%d groups, nextToken=%q",
		len(page1.Response), len(page2.Response), page2.NextToken)
}

func SetupK8sListTargetsTest(t *testing.T, cfg K8sListTargetsConfig, requireConfiguredTarget bool) *K8sTestContext {
	t.Helper()
	skipUnlessSupportedSCAEnv(t)

	testCtx := loadListTargetsTestContext(t, cfg.ConfigBlockKey)
	if requireConfiguredTarget {
		require.NotEmpty(t, testCtx.Targets, "%s.targets.targets array is required", cfg.ConfigBlockKey)
	}
	return testCtx
}

func K8sTargetFromConfig(t *testing.T, cfg K8sListTargetsConfig, testCtx *K8sTestContext, targetIndex int) K8sTargetConfig {
	t.Helper()
	require.Greater(t, len(testCtx.Targets), targetIndex, "configured k8s target index %d is required", targetIndex)

	target := cfg.BuildTarget(testCtx.Targets[targetIndex])
	t.Logf("Using target from config: workspaceId=%s workspaceName=%s roleId=%s roleName=%s orgId=%s workspaceType=%s clusterId=%s scope=%s",
		target.PolicyTarget.WorkspaceID, target.PolicyTarget.WorkspaceName, target.PolicyTarget.RoleInfo.ID, target.PolicyTarget.RoleInfo.Name,
		target.PolicyTarget.OrganizationID, target.PolicyTarget.WorkspaceType, target.ClusterID, target.Scope)
	return target
}

func MustPrincipalK8sService(t *testing.T, testCtx *K8sTestContext) *k8sservice.IdsecSCAK8sService {
	t.Helper()

	k8sSvc, err := buildPrincipalK8sService(t, testCtx.AuthBlock, testCtx.PrincipalBlock)
	require.NoError(t, err)
	return k8sSvc
}

func ListK8sTargets(
	t *testing.T,
	k8sSvc *k8sservice.IdsecSCAK8sService,
	CSP string,
	workspaceID string,
	limit int,
) *k8smodels.IdsecSCAk8sListClustersResponse {
	t.Helper()

	resp, err := k8sSvc.ListTargets(&k8smodels.IdsecSCAk8sListClustersRequest{
		CSP:         CSP,
		WorkspaceID: workspaceID,
		Limit:       limit,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	logK8sListTargetsResponse(t, "K8s ListTargets response", resp)
	return resp
}

func ListK8sTargetsWithNextToken(
	t *testing.T,
	k8sSvc *k8sservice.IdsecSCAK8sService,
	cfg K8sListTargetsConfig,
) (*k8smodels.IdsecSCAk8sListClustersResponse, *k8smodels.IdsecSCAk8sListClustersResponse) {
	t.Helper()

	page1 := ListK8sTargets(t, k8sSvc, cfg.CSP, "", 1)
	require.Len(t, page1.Response, 1, "expected exactly one cluster target on the first page with limit=1")
	if page1.Total < 2 || page1.NextToken == nil || strings.TrimSpace(*page1.NextToken) == "" {
		t.Skipf("%s pagination skipped: live K8s ListTargets did not return a second page: total=%d nextToken=%q", cfg.DisplayName, page1.Total, k8sNextTokenString(page1.NextToken))
	}

	page2, err := k8sSvc.ListTargets(&k8smodels.IdsecSCAk8sListClustersRequest{
		CSP:       cfg.CSP,
		Limit:     1,
		NextToken: *page1.NextToken,
	})
	require.NoError(t, err)
	require.Len(t, page2.Response, 1, "expected exactly one cluster target on the second page with limit=1")
	logK8sListTargetsResponse(t, "K8s ListTargets page 2 response", page2)
	return page1, page2
}

func logK8sListTargetsResponse(t *testing.T, label string, resp *k8smodels.IdsecSCAk8sListClustersResponse) {
	t.Helper()

	responseJSON, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		t.Logf("%s: unable to marshal response: %v", label, err)
		return
	}
	t.Logf("%s:\n%s", label, string(responseJSON))
}

func VerifyK8sPagination(
	t *testing.T,
	page1 *k8smodels.IdsecSCAk8sListClustersResponse,
	page2 *k8smodels.IdsecSCAk8sListClustersResponse,
) {
	t.Helper()

	require.NotEqual(t, k8sPaginationTargetKey(page1.Response[0]), k8sPaginationTargetKey(page2.Response[0]),
		"expected pagination to return a different cluster target on the second page")
	t.Logf("Pagination: page1=%d targets, page2=%d targets, nextToken=%q",
		len(page1.Response), len(page2.Response), k8sNextTokenString(page2.NextToken))
}

func VerifyK8sFilteredTargets(
	t *testing.T,
	target K8sTargetConfig,
	filteredResp *k8smodels.IdsecSCAk8sListClustersResponse,
) {
	t.Helper()

	require.NotEmpty(t, filteredResp.Response, "Workspace-filtered K8s ListTargets response should not be empty")
	verifyK8sClusterTargetInListTargets(t, target.VerifyTarget, target.ClusterID, target.Scope, target.FQDN, filteredResp.Response)
}

// VerifyAWSKubeconfigEligibilityDetails checks that generated kubeconfig YAML matches
// the eligible AWS K8s target and includes the idsec kubectl-login/elevate exec hook.
func VerifyAWSKubeconfigEligibilityDetails(t *testing.T, kubeconfigYAML string, target K8sTargetConfig) {
	t.Helper()

	var parsed kubeconfigFile
	require.NoError(t, yaml.Unmarshal([]byte(kubeconfigYAML), &parsed), "generated kubeconfig should be valid YAML")
	require.Equal(t, "v1", parsed.APIVersion, "generated kubeconfig apiVersion mismatch")
	require.Equal(t, "Config", parsed.Kind, "generated kubeconfig kind mismatch")
	require.NotEmpty(t, parsed.Clusters, "generated kubeconfig should include clusters")
	require.NotEmpty(t, parsed.Contexts, "generated kubeconfig should include contexts")
	require.NotEmpty(t, parsed.Users, "generated kubeconfig should include users")
	require.NotEmpty(t, parsed.CurrentContext, "generated kubeconfig should set current-context")

	expectedFQDN := strings.TrimPrefix(strings.TrimSpace(target.FQDN), "https://")
	require.Contains(t, kubeconfigYAML, expectedFQDN, "generated kubeconfig should include the eligible cluster FQDN")

	require.NotNil(t, target.VerifyTarget, "expected K8s target model must not be nil")
	expectedRoleID := strings.TrimSpace(target.VerifyTarget.RoleInfo.ID)
	expectedRoleName := strings.TrimSpace(target.VerifyTarget.RoleInfo.Name)
	hasExpectedRole := strings.Contains(kubeconfigYAML, expectedRoleID) || strings.Contains(kubeconfigYAML, expectedRoleName)
	require.True(t, hasExpectedRole, "generated kubeconfig should include the eligible role ID or role name")
	require.Contains(t, strings.ToLower(kubeconfigYAML), "aws", "generated kubeconfig should include AWS CSP details")

	require.True(t, hasKubectlLoginExecPlugin(parsed), "generated kubeconfig should include the idsec kubectl-login/elevate exec plugin")

}

// hasKubectlLoginExecPlugin confirms kubectl can call back into idsec for credentials.
func hasKubectlLoginExecPlugin(parsed kubeconfigFile) bool {
	for _, user := range parsed.Users {
		execCommand := user.User.Exec.Command
		execArgs := strings.Join(user.User.Exec.Args, " ")
		execInvocation := execCommand + " " + execArgs
		if strings.Contains(execInvocation, "kubectl-login") || strings.Contains(execInvocation, "elevate") {
			return true
		}
	}
	return false
}

func ElevateK8sKubeloginTarget(
	t *testing.T,
	k8sSvc *k8sservice.IdsecSCAK8sService,
	target K8sTargetConfig,
) *k8smodels.IdsecSCAK8sElevateResponse {
	t.Helper()

	elevateResp, err := k8sSvc.Elevate(&k8smodels.IdsecSCAK8sElevateKubectlRequest{
		CSP:    "aws",
		FQDN:   target.FQDN,
		RoleID: target.PolicyTarget.RoleInfo.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, elevateResp)
	return elevateResp
}

func VerifyAWSK8sKubelogin(
	t *testing.T,
	elevateResp *k8smodels.IdsecSCAK8sElevateResponse,
	target K8sTargetConfig,
) {
	t.Helper()

	require.NotNil(t, elevateResp, "kubelogin elevate response should not be nil")
	require.Equal(t, "AWS", strings.ToUpper(strings.TrimSpace(elevateResp.Response.CSP)))
	require.Len(t, elevateResp.Response.Results, 1, "kubelogin elevate should return one result")

	elevateResult := elevateResp.Response.Results[0]
	require.Equal(t, target.PolicyTarget.WorkspaceID, strings.TrimSpace(elevateResult.WorkspaceID), "kubelogin workspace ID mismatch")
	require.Equal(t, target.PolicyTarget.RoleInfo.ID, strings.TrimSpace(elevateResult.RoleID), "kubelogin role ID mismatch")
	require.NotEmpty(t, elevateResult.SessionID, "kubelogin should return a session ID")
	require.NotEmpty(t, elevateResult.AccessCredentials, "kubelogin should return AWS access credentials")
	require.Equal(t, target.ClusterID, strings.TrimSpace(elevateResult.TargetID), "kubelogin target ID mismatch")

	region, clusterName, err := k8sservice.ParseEKSARN(elevateResult.TargetID)
	require.NoError(t, err)
	require.NotEmpty(t, region, "kubelogin should derive AWS region from target ID")
	require.NotEmpty(t, clusterName, "kubelogin should derive EKS cluster name from target ID")

	tokenProvider, err := k8sservice.GetTokenProvider("AWS")
	require.NoError(t, err)
	execCredential, err := tokenProvider.GenerateToken(&elevateResult, &k8sservice.IdsecSCAK8sClusterContext{
		CSP:       "AWS",
		RoleID:    target.PolicyTarget.RoleInfo.ID,
		FQDN:      target.FQDN,
		Region:    region,
		ClusterID: clusterName,
	})
	require.NoError(t, err)
	require.NotNil(t, execCredential)
	require.Equal(t, "client.authentication.k8s.io/v1beta1", execCredential.APIVersion)
	require.Equal(t, "ExecCredential", execCredential.Kind)
	require.True(t, strings.HasPrefix(execCredential.Status.Token, "k8s-aws-v1."), "kubelogin should generate an EKS bearer token")
}

func k8sNextTokenString(nextToken *string) string {
	if nextToken == nil {
		return ""
	}
	return *nextToken
}

func verifyK8sClusterTargetInListTargets(
	t *testing.T,
	expectedTarget *scacloudaccessmodels.IdsecSCAEligibleTarget,
	expectedClusterID string,
	expectedScope string,
	expectedFQDN string,
	listResponse []k8smodels.IdsecSCAk8sListClustersEligibleTarget,
) {
	t.Helper()

	require.NotNil(t, expectedTarget, "Expected K8s target must not be nil")

	expectedRoleID := strings.TrimSpace(expectedTarget.RoleInfo.ID)
	expectedRoleName := strings.TrimSpace(expectedTarget.RoleInfo.Name)
	expectedWorkspaceID := strings.TrimSpace(expectedTarget.WorkspaceID)
	expectedWorkspaceName := strings.TrimSpace(expectedTarget.WorkspaceName)
	expectedOrganizationID := strings.TrimSpace(expectedTarget.OrganizationID)
	expectedWorkspaceType := strings.TrimSpace(expectedTarget.WorkspaceType)
	expectedClusterID = strings.TrimSpace(expectedClusterID)
	expectedScope = strings.TrimSpace(expectedScope)
	expectedFQDN = strings.TrimSpace(expectedFQDN)
	t.Logf("Expected K8s target: roleId=%s roleName=%s workspaceId=%s workspaceName=%s orgId=%s workspaceType=%s clusterId=%s scope=%s fqdn=%s",
		expectedRoleID, expectedRoleName, expectedWorkspaceID, expectedWorkspaceName, expectedOrganizationID, expectedWorkspaceType, expectedClusterID, expectedScope, expectedFQDN)

	require.NotEmpty(t, listResponse, "K8s ListTargets: response should not be empty")

	for _, actualTarget := range listResponse {
		actualRoleID := strings.TrimSpace(actualTarget.Role.ID)
		actualRoleName := strings.TrimSpace(actualTarget.Role.Name)
		actualWorkspaceID := strings.TrimSpace(actualTarget.WorkspaceID)
		actualWorkspaceName := strings.TrimSpace(actualTarget.WorkspaceName)
		actualWorkspaceType := strings.TrimSpace(actualTarget.WorkspaceType)
		actualClusterID := strings.TrimSpace(actualTarget.Target.ClusterID)
		actualScope := strings.TrimSpace(actualTarget.Target.Scope)
		var actualFQDN string
		if actualTarget.Target.FQDN != nil {
			actualFQDN = strings.TrimSpace(*actualTarget.Target.FQDN)
		}
		var actualOrganizationID string
		if actualTarget.OrganizationID != nil {
			actualOrganizationID = strings.TrimSpace(*actualTarget.OrganizationID)
		}
		if actualRoleID == expectedRoleID && actualWorkspaceID == expectedWorkspaceID {
			if expectedRoleName != "" {
				require.Equal(t, expectedRoleName, actualRoleName, "K8s ListTargets: role name mismatch")
			}
			if expectedWorkspaceName != "" {
				require.Equal(t, expectedWorkspaceName, actualWorkspaceName, "K8s ListTargets: workspace name mismatch")
			}
			if expectedOrganizationID != "" && actualOrganizationID != "" {
				require.Equal(t, expectedOrganizationID, actualOrganizationID, "K8s ListTargets: organization ID mismatch")
			}
			if expectedWorkspaceType != "" {
				require.Equal(t, expectedWorkspaceType, actualWorkspaceType, "K8s ListTargets: workspace type mismatch")
			}
			if expectedClusterID != "" {
				require.Equal(t, expectedClusterID, actualClusterID, "K8s ListTargets: cluster ID mismatch")
			}
			if expectedScope != "" {
				require.Equal(t, expectedScope, actualScope, "K8s ListTargets: scope mismatch")
			}
			if expectedFQDN != "" {
				require.Equal(t, expectedFQDN, actualFQDN, "K8s ListTargets: fqdn mismatch")
			}
			t.Logf("K8s policy target validated via ListTargets: roleId=%s roleName=%s workspaceId=%s workspaceName=%s orgId=%s workspaceType=%s clusterId=%s scope=%s fqdn=%s",
				actualRoleID, actualRoleName, actualWorkspaceID, actualWorkspaceName, actualOrganizationID, actualWorkspaceType, actualClusterID, actualScope, actualFQDN)
			return
		}
	}

	require.Failf(t, "K8s ListTargets target mismatch",
		"Expected K8s target not found in ListTargets response: roleId=%s roleName=%s workspaceId=%s workspaceName=%s orgId=%s workspaceType=%s clusterId=%s scope=%s fqdn=%s",
		expectedRoleID, expectedRoleName, expectedWorkspaceID, expectedWorkspaceName, expectedOrganizationID, expectedWorkspaceType, expectedClusterID, expectedScope, expectedFQDN)
}

func verifyCloudAccessTargetInListTargets(
	t *testing.T,
	fetchedPolicy *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy,
	listResponse []scacloudaccessmodels.IdsecSCAEligibleTarget,
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

func VerifyGroupAccessTargetInListTargets(
	t *testing.T,
	fetchedPolicy *groupaccessmodels.IdsecPolicyGroupAccessPolicy,
	listResponse []scagroupaccessmodels.IdsecSCAGroupsEligibleTarget,
) {
	t.Helper()

	logJSON(t, "Actual GroupAccess ListTargets response", listResponse)
	require.NotNil(t, fetchedPolicy, "GetPolicy response must not be nil")
	require.Len(t, fetchedPolicy.Targets.Targets, 1, "GetPolicy: expected exactly one group access target")

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

// k8sPaginationTargetKey returns a compound key used to compare two eligible
// K8s targets for equality during pagination verification.
func k8sPaginationTargetKey(target k8smodels.IdsecSCAk8sListClustersEligibleTarget) string {
	var organizationID string
	if target.OrganizationID != nil {
		organizationID = strings.TrimSpace(*target.OrganizationID)
	}
	return strings.Join([]string{
		strings.TrimSpace(target.WorkspaceID),
		strings.TrimSpace(target.Role.ID),
		organizationID,
		strings.TrimSpace(target.WorkspaceType),
		strings.TrimSpace(target.Target.Scope),
		strings.TrimSpace(target.Target.ClusterID),
	}, "|")
}

// ---------------------------------------------------------------------------
// AWS Cloud Access target verification
// ---------------------------------------------------------------------------

// verifyAWSCloudAccessTargetInListTargets checks that the AWS account target
// appears in the ListTargets response. Matches on roleId and workspaceId.
func verifyAWSCloudAccessTargetInListTargets(
	t *testing.T,
	expectedTarget *scacloudaccessmodels.IdsecSCAEligibleTarget,
	listResponse []scacloudaccessmodels.IdsecSCAEligibleTarget,
) {
	t.Helper()

	require.NotNil(t, expectedTarget, "Expected AWS target must not be nil")

	expectedRoleID := strings.TrimSpace(expectedTarget.RoleInfo.ID)
	expectedRoleName := strings.TrimSpace(expectedTarget.RoleInfo.Name)
	expectedWorkspaceID := strings.TrimSpace(expectedTarget.WorkspaceID)
	expectedWorkspaceName := strings.TrimSpace(expectedTarget.WorkspaceName)
	expectedOrganizationID := strings.TrimSpace(expectedTarget.OrganizationID)
	expectedWorkspaceType := strings.TrimSpace(expectedTarget.WorkspaceType)
	t.Logf("Expected AWS target: roleId=%s roleName=%s workspaceId=%s workspaceName=%s orgId=%s workspaceType=%s",
		expectedRoleID, expectedRoleName, expectedWorkspaceID, expectedWorkspaceName, expectedOrganizationID, expectedWorkspaceType)

	require.NotEmpty(t, listResponse, "ListTargets: response should not be empty")

	for _, actualTarget := range listResponse {
		actualRoleID := strings.TrimSpace(actualTarget.RoleInfo.ID)
		actualWorkspaceID := strings.TrimSpace(actualTarget.WorkspaceID)
		if actualRoleID == expectedRoleID && actualWorkspaceID == expectedWorkspaceID {
			if expectedRoleName != "" {
				require.Equal(t, expectedRoleName, strings.TrimSpace(actualTarget.RoleInfo.Name), "ListTargets: role name mismatch")
			}
			if expectedWorkspaceName != "" {
				require.Equal(t, expectedWorkspaceName, strings.TrimSpace(actualTarget.WorkspaceName), "ListTargets: workspace name mismatch")
			}
			t.Logf("AWS policy target validated via ListTargets: roleId=%s workspaceId=%s", actualRoleID, actualWorkspaceID)
			return
		}
	}

	require.Failf(t, "ListTargets target mismatch",
		"Expected AWS target not found in ListTargets: roleId=%s workspaceId=%s",
		expectedRoleID, expectedWorkspaceID)
}

type awsAccessCredentials struct {
	AccessKeyID     string `json:"aws_access_key"`
	SecretAccessKey string `json:"aws_secret_access_key"`
	SessionToken    string `json:"aws_session_token"`
}

func requireAWSAccessCredentials(t *testing.T, accessCredentials string) awsAccessCredentials {
	t.Helper()

	var awsCreds awsAccessCredentials
	require.NoError(t, json.Unmarshal([]byte(accessCredentials), &awsCreds), "Elevate: accessCredentials should be JSON")
	require.NotEmpty(t, awsCreds.AccessKeyID, "Elevate: expected aws_access_key")
	require.NotEmpty(t, awsCreds.SecretAccessKey, "Elevate: expected aws_secret_access_key")
	require.NotEmpty(t, awsCreds.SessionToken, "Elevate: expected aws_session_token")
	return awsCreds
}

func verifyAWSAccessCredentialsIdentity(
	t *testing.T,
	awsCreds awsAccessCredentials,
	target *scacloudaccessmodels.IdsecSCAEligibleTarget,
) {
	t.Helper()

	// Use the returned temporary credentials against AWS STS to prove they are
	// accepted by AWS, then verify they belong to the requested account and role.
	stsClient := sts.NewFromConfig(aws.Config{
		Region: "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(
			awsCreds.AccessKeyID,
			awsCreds.SecretAccessKey,
			awsCreds.SessionToken,
		),
	})
	identity, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	require.NoError(t, err, "Elevate: returned AWS credentials should be usable with STS GetCallerIdentity")
	require.NotNil(t, identity, "Elevate: STS GetCallerIdentity response should not be nil")

	require.Equal(t, strings.TrimSpace(target.WorkspaceID), strings.TrimSpace(aws.ToString(identity.Account)),
		"Elevate: AWS credentials account should match requested workspace")
	if roleName := strings.TrimSpace(target.RoleInfo.Name); roleName != "" {
		require.Contains(t, strings.TrimSpace(aws.ToString(identity.Arn)), ":assumed-role/"+roleName+"/",
			"Elevate: AWS credentials should be for the requested role")
	}
}

// cloudAccessPaginationTargetKey returns a compound key used to compare
// two eligible targets for equality during pagination verification.
func cloudAccessPaginationTargetKey(target scacloudaccessmodels.IdsecSCAEligibleTarget) string {
	return strings.Join([]string{
		strings.TrimSpace(target.WorkspaceID),
		strings.TrimSpace(target.RoleInfo.ID),
		strings.TrimSpace(target.OrganizationID),
		strings.TrimSpace(target.WorkspaceType),
	}, "|")
}

// groupAccessPaginationTargetKey returns a compound key used to compare
// two eligible group targets for equality during pagination verification.
func groupAccessPaginationTargetKey(target scagroupaccessmodels.IdsecSCAGroupsEligibleTarget) string {
	return strings.Join([]string{
		strings.TrimSpace(target.GroupID),
		strings.TrimSpace(target.DirectoryID),
	}, "|")
}

// ---------------------------------------------------------------------------
// Shared Azure Cloud Access E2E flows
// ---------------------------------------------------------------------------

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
