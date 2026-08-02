//go:build (e2e && policy) || e2e

// Package policy contains E2E tests for the SDK's infrastructure access
// policy services (VM, DB, ...).
package policy

import (
	"strings"
	"testing"

	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"

	usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

// createDualControlUser provisions a throwaway Identity user to act as a
// policy principal or approver (the backend rejects unknown IDs before
// evaluating dual control), and registers its deletion as test cleanup.
func createDualControlUser(t *testing.T, ctx *framework.TestContext, namePrefix string) *usersmodels.IdsecIdentityUser {
	t.Helper()

	svc, err := ctx.API.IdentityUsers()
	if err != nil {
		t.Fatalf("Failed to get Identity Users service: %v", err)
	}

	username := framework.RandomResourceName(namePrefix)
	created, err := svc.Create(&usersmodels.IdsecIdentityCreateUser{Username: username})
	if err != nil {
		t.Fatalf("Failed to create Identity user %q for dual-control fixture: %v", username, err)
	}

	ctx.TrackResourceByType("IdentityUser", created.UserID, func() error {
		return svc.Delete(&usersmodels.IdsecIdentityDeleteUser{UserID: created.UserID})
	})

	return created
}

// userToPolicyPrincipal converts a freshly created Identity user into a
// policy principal reference (for either the principal or approver slot).
// SourceDirectoryID uses the tenant suffix from the username (the part
// after '@') since that's the only tenant-identifying value available
// without an extra directories lookup.
func userToPolicyPrincipal(user *usersmodels.IdsecIdentityUser) policycommonmodels.IdsecPolicyPrincipal {
	return policycommonmodels.IdsecPolicyPrincipal{
		Type:                policycommonmodels.PrincipalTypeUser,
		ID:                  user.UserID,
		Name:                user.Username,
		SourceDirectoryName: "CyberArk",
		SourceDirectoryID:   tenantSuffix(user.Username),
	}
}

func tenantSuffix(username string) string {
	if idx := strings.LastIndex(username, "@"); idx != -1 {
		return username[idx+1:]
	}
	return username
}
