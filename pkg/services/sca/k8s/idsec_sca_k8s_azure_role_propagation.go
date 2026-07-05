package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/golang-jwt/jwt/v5"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	rolePropagationTimeout = 1 * time.Minute

	// Polling schedule: poll at t=0, then sleep rolePropagationFastInterval
	// rolePropagationFastAttempts times (t=1,2,3s by default), then keep
	// polling every rolePropagationSlowInterval until rolePropagationTimeout.
	rolePropagationFastInterval = 1 * time.Second
	rolePropagationFastAttempts = 3
	rolePropagationSlowInterval = 3 * time.Second
)

// AzureSubscriptionFromTargetID extracts the subscription GUID from an Elevate targetId ARM path.
func AzureSubscriptionFromTargetID(targetID string) string {
	subscriptionID, _, err := azureClusterScopeFromTargetID(targetID)
	if err != nil {
		return ""
	}
	return subscriptionID
}

// WaitForAzureRolePropagation polls ARM until the Elevate-granted role assignment
// for principalOID is visible, or rolePropagationTimeout elapses.
//
// principalOID is the az login user's object id; callers obtain it via
// ExtractAzurePrincipalOID on the AKS access token already in hand, which
// avoids a second `az` subprocess just to mint a management-scoped token.
//
// diagnostics controls kubectl-login stderr logs; when false, polling is silent.
//
// Poll schedule: immediate, then 1s,1s,1s, then every 3s until 60s budget
// is exhausted.
func WaitForAzureRolePropagation(
	organizationID string,
	elevateResult *k8smodels.IdsecSCAK8sElevateResult,
	principalOID string,
	diagnostics bool,
) error {
	if elevateResult == nil {
		return fmt.Errorf("elevate result is required for role propagation check")
	}
	if strings.TrimSpace(principalOID) == "" {
		return fmt.Errorf("principal OID is required for role propagation check")
	}

	subscriptionID, scope, err := azureClusterScopeFromTargetID(elevateResult.TargetID)
	if err != nil {
		return err
	}
	roleDefGUID, err := azureRoleDefinitionGUID(elevateResult.RoleID)
	if err != nil {
		return err
	}

	cred, err := newAzureCLICredential(organizationID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), rolePropagationTimeout)
	defer cancel()

	if diagnostics {
		KubectlLoginLog(KubectlLoginLogLevelInfo,
			"waiting for Azure role propagation (role=%s scope=%s; budget %s)",
			roleDefGUID, scope, rolePropagationTimeout,
		)
	}

	client, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("create role assignments client: %w", err)
	}

	deadline := time.Now().Add(rolePropagationTimeout)
	for attempt := 1; ; attempt++ {
		found, listErr := azureRoleAssignmentVisible(ctx, client, scope, principalOID, roleDefGUID)
		if listErr != nil {
			return fmt.Errorf("list role assignments (attempt %d): %w", attempt, listErr)
		}
		if found {
			if diagnostics {
				KubectlLoginLog(KubectlLoginLogLevelInfo,
					"Azure role propagation confirmed (attempt %d)",
					attempt,
				)
			}
			return nil
		}

		wait := rolePropagationFastInterval
		if attempt > rolePropagationFastAttempts {
			wait = rolePropagationSlowInterval
		}
		if time.Now().Add(wait).After(deadline) {
			break
		}

		if diagnostics {
			KubectlLoginLog(KubectlLoginLogLevelDebug,
				"role not visible in ARM yet (attempt %d), retrying in %s...",
				attempt, wait,
			)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"azure role propagation not confirmed within %s — retry kubectl after the role assignment appears in Azure (ARM APIs can lag after Elevate)",
				rolePropagationTimeout,
			)
		case <-time.After(wait):
		}
	}

	return fmt.Errorf(
		"azure role propagation not confirmed within %s — retry the kubectl command",
		rolePropagationTimeout,
	)
}

func newAzureCLICredential(organizationID string) (azcore.TokenCredential, error) {
	opts := &azidentity.AzureCLICredentialOptions{}
	if strings.TrimSpace(organizationID) != "" {
		opts.TenantID = strings.TrimSpace(organizationID)
	}
	return azidentity.NewAzureCLICredential(opts)
}

// ExtractAzurePrincipalOID returns the oid (or sub) claim from an Azure access
// token JWT. Signature is not verified — callers must trust the token source.
func ExtractAzurePrincipalOID(accessToken string) (string, error) {
	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("parse az token JWT: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("unexpected JWT claims type")
	}
	for _, key := range []string{"oid", "sub"} {
		if val, exists := claims[key]; exists {
			if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s), nil
			}
		}
	}
	return "", fmt.Errorf("az token has no oid/sub claim")
}

func azureClusterScopeFromTargetID(targetID string) (subscriptionID, scope string, err error) {
	targetID = strings.TrimSpace(strings.TrimSuffix(targetID, "/"))
	if targetID == "" {
		return "", "", fmt.Errorf("elevate targetId is empty")
	}
	lower := strings.ToLower(targetID)
	const subPrefix = "/subscriptions/"
	if !strings.HasPrefix(lower, subPrefix) {
		return "", "", fmt.Errorf("elevate targetId %q is not a subscription-scoped ARM path", targetID)
	}
	rest := targetID[len(subPrefix):]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return "", "", fmt.Errorf("elevate targetId %q has no path after subscription", targetID)
	}
	return rest[:slash], targetID, nil
}

func azureRoleDefinitionGUID(roleID string) (string, error) {
	roleID = strings.TrimSpace(roleID)
	if roleID == "" {
		return "", fmt.Errorf("elevate roleId is empty")
	}
	const marker = "roleDefinitions/"
	if idx := strings.LastIndex(strings.ToLower(roleID), strings.ToLower(marker)); idx >= 0 {
		return roleID[idx+len(marker):], nil
	}
	if !strings.Contains(roleID, "/") {
		return roleID, nil
	}
	return "", fmt.Errorf("elevate roleId %q is not a role definition ARM id or GUID", roleID)
}

func azureRoleAssignmentVisible(
	ctx context.Context,
	client *armauthorization.RoleAssignmentsClient,
	scope, principalOID, roleDefGUID string,
) (bool, error) {
	assignments, err := listAzureRoleAssignmentsForPrincipal(ctx, client, scope, principalOID)
	if err != nil {
		return false, err
	}
	for _, ra := range assignments {
		if ra.Properties == nil {
			continue
		}
		assignedPrincipal := azureStringPtr(ra.Properties.PrincipalID)
		assignedRoleDef := azureStringPtr(ra.Properties.RoleDefinitionID)
		if strings.EqualFold(assignedPrincipal, principalOID) &&
			azureRoleDefinitionsMatch(assignedRoleDef, roleDefGUID) {
			return true, nil
		}
	}
	return false, nil
}

func listAzureRoleAssignmentsForPrincipal(
	ctx context.Context,
	client *armauthorization.RoleAssignmentsClient,
	scope, principalOID string,
) ([]*armauthorization.RoleAssignment, error) {
	filter := fmt.Sprintf("assignedTo('%s')", principalOID)
	pager := client.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: to.Ptr(filter),
	})
	var out []*armauthorization.RoleAssignment
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if strings.Contains(err.Error(), "UnsupportedQuery") || strings.Contains(err.Error(), "400") {
				return listAzureRoleAssignmentsAtScope(ctx, client, scope, principalOID)
			}
			return nil, err
		}
		out = append(out, page.Value...)
	}
	if len(out) == 0 {
		return listAzureRoleAssignmentsAtScope(ctx, client, scope, principalOID)
	}
	return out, nil
}

func listAzureRoleAssignmentsAtScope(
	ctx context.Context,
	client *armauthorization.RoleAssignmentsClient,
	scope, principalOID string,
) ([]*armauthorization.RoleAssignment, error) {
	pager := client.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: to.Ptr("atScope()"),
	})
	var out []*armauthorization.RoleAssignment
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ra := range page.Value {
			if ra.Properties == nil {
				continue
			}
			if strings.EqualFold(azureStringPtr(ra.Properties.PrincipalID), principalOID) {
				out = append(out, ra)
			}
		}
	}
	return out, nil
}

func azureRoleDefinitionsMatch(assignedFromAPI, expectedGUID string) bool {
	assigned := strings.ToLower(strings.TrimSpace(assignedFromAPI))
	expected := strings.ToLower(strings.TrimSpace(expectedGUID))
	if assigned == expected {
		return true
	}
	const marker = "roledefinitions/"
	if idx := strings.LastIndex(assigned, marker); idx >= 0 {
		return assigned[idx+len(marker):] == expected
	}
	return false
}

func azureStringPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
