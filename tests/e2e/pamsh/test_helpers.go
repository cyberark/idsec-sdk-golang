//go:build (e2e && pamsh) || e2e

package pamsh

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pamshaccounts "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"
	pamshsafes "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

const (
	// pamshE2ESafeNameMaxLen is the maximum PAS safe name length accepted by PVWA.
	pamshE2ESafeNameMaxLen = 28
	// pamshE2ESafeNameSuffixLen is the length added by framework.RandomResourceName ("-" + 8 random chars).
	pamshE2ESafeNameSuffixLen = 9

	// pamshWorkflowSafeMemberUser is the dedicated PAS user added as a safe member in pamsh e2e
	// (not a built-in system group like PVWAAppUsers).
	pamshWorkflowSafeMemberUser = "e2e-test-safe-member-user"
	// pamshE2EActivePlatformID is the CyberArk account platform ID used when pamsh e2e testutils
	// create pamshaccounts (typical PAS installs expose UnixSSH; pcloud workflow testutils often use WinLooselyDevice).
	pamshE2EActivePlatformID = "UnixSSH"
)

// pamshDeleteNotFoundMarker is the substring pamcommon uses when formatting delete errors:
// fmt.Errorf("failed to delete … - [%d] - …", statusCode, body) with statusCode 404.
const pamshDeleteNotFoundMarker = " - [404] - "

// pamshDeleteErrorIsNotFound reports whether err is a pamsh/PVWA delete response indicating the
// resource is already absent (HTTP 404), matching the stable error string from pamcommon APIs.
func pamshDeleteErrorIsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), pamshDeleteNotFoundMarker)
}

// pamshDeleteCleanupResult maps delete errors for framework cleanup: nil and 404 become nil
// (404 logged as benign); any other error is returned so CleanupStack fails the test.
func pamshDeleteCleanupResult(t *testing.T, resourceLabel string, err error) error {
	t.Helper()
	if err == nil {
		return nil
	}
	if pamshDeleteErrorIsNotFound(err) {
		t.Logf("delete %s: resource already removed (404): %v", resourceLabel, err)
		return nil
	}
	return err
}

func intPtr(i int) *int {
	return &i
}

func requirePamshPVWAConfig(t *testing.T, ctx *framework.TestContext) *framework.PVWAProviderConfig {
	t.Helper()

	require.True(t, ctx.HasAuthenticator("pvwa"),
		"pamsh e2e requires PVWA; set IDSEC_E2E_PVWA_URL, IDSEC_E2E_PVWA_USERNAME, IDSEC_E2E_PVWA_SECRET (see testutils/e2e/README.md)")

	pvwaProfile, hasPVWA := ctx.Config.AuthProfiles["pvwa"]
	require.True(t, hasPVWA, "e2e config must include a pvwa auth profile when running pamsh testutils")

	cfg, ok := pvwaProfile.(*framework.PVWAProviderConfig)
	require.True(t, ok, "expected *framework.PVWAProviderConfig for pvwa profile, got %T", pvwaProfile)
	return cfg
}

func pamshAccountsService(t *testing.T, ctx *framework.TestContext) *pamshaccounts.IdsecPamshAccountsService {
	t.Helper()

	_ = requirePamshPVWAConfig(t, ctx)
	accountsSvc, err := ctx.API.PamshAccounts()
	require.NoError(t, err, "PamshAccounts: ensure pamsh-pamshaccounts is registered and pvwa authenticator is present")
	return accountsSvc
}

func pamshSafesService(t *testing.T, ctx *framework.TestContext) *pamshsafes.IdsecPamshSafesService {
	t.Helper()

	_ = requirePamshPVWAConfig(t, ctx)
	safesSvc, err := ctx.API.PamshSafes()
	require.NoError(t, err, "PamshSafes: ensure pamsh-pamshsafes is registered and pvwa authenticator is present")
	return safesSvc
}

// pamshSafeMemberName returns the PAS user name to add as a safe member in pamsh e2e testutils
// (MemberType User).
func pamshSafeMemberName(t *testing.T) string {
	t.Helper()
	return pamshWorkflowSafeMemberUser
}

// pamshRandomSafeName returns a unique safe name within PAS length limits (max 28 characters).
func pamshRandomSafeName(prefix string) string {
	maxPrefix := pamshE2ESafeNameMaxLen - pamshE2ESafeNameSuffixLen
	if len(prefix) > maxPrefix {
		prefix = prefix[:maxPrefix]
	}
	name := framework.RandomResourceName(prefix)
	if len(name) > pamshE2ESafeNameMaxLen {
		return name[:pamshE2ESafeNameMaxLen]
	}
	return name
}

// createPamshTestSafe creates a safe with a unique name (RandomResourceName(namePrefix)),
// registers it for deletion on ctx cleanup, and returns the created safe.
func createPamshTestSafe(t *testing.T, ctx *framework.TestContext, description, namePrefix string) *safesmodels.IdsecPamshSafe {
	t.Helper()

	safesSvc := pamshSafesService(t, ctx)
	safeName := pamshRandomSafeName(namePrefix)
	t.Logf("Creating PAMSH test safe: %s", safeName)

	safe, err := safesSvc.Create(&safesmodels.IdsecPamshAddSafe{
		SafeName:    safeName,
		Description: description,
	})
	require.NoError(t, err, "Failed to create PAMSH test safe")

	ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
		delErr := safesSvc.Delete(&safesmodels.IdsecPamshDeleteSafe{
			SafeID: safe.SafeID,
		})
		return pamshDeleteCleanupResult(t, "Safe "+safe.SafeName, delErr)
	})

	return safe
}

// createPamshWorkflowSafe creates a workflow-style safe (NumberOfDaysRetention 0 for immediate deletion),
// registers cleanup, and returns the created safe.
func createPamshWorkflowSafe(t *testing.T, ctx *framework.TestContext, description, namePrefix string) *safesmodels.IdsecPamshSafe {
	t.Helper()

	safesSvc := pamshSafesService(t, ctx)
	safeName := pamshRandomSafeName(namePrefix)
	t.Logf("Creating PAMSH workflow safe: %s", safeName)

	safe, err := safesSvc.Create(&safesmodels.IdsecPamshAddSafe{
		SafeName:              safeName,
		Description:           description,
		NumberOfDaysRetention: intPtr(0),
	})
	require.NoError(t, err, "Failed to create PAMSH workflow safe")
	require.NotNil(t, safe)

	ctx.TrackResourceByType("Safe", safe.SafeName, func() error {
		t.Logf("Cleaning up safe: %s", safe.SafeName)
		delErr := safesSvc.Delete(&safesmodels.IdsecPamshDeleteSafe{
			SafeID: safe.SafeID,
		})
		return pamshDeleteCleanupResult(t, "Safe "+safe.SafeName, delErr)
	})

	return safe
}

// createPamshTestAccount creates an account and registers deferred delete cleanup (LIFO before safe).
func createPamshTestAccount(t *testing.T, ctx *framework.TestContext, accountsSvc *pamshaccounts.IdsecPamshAccountsService, req *accountsmodels.IdsecPamshAddAccount) *accountsmodels.IdsecPamshAccount {
	t.Helper()

	account, err := accountsSvc.Create(req)
	require.NoError(t, err, "Failed to create PAMSH test account")
	require.NotNil(t, account)

	accountID := account.AccountID
	ctx.TrackResourceByType("Account", account.Name, func() error {
		t.Logf("Cleaning up account: %s", accountID)
		delErr := accountsSvc.Delete(&accountsmodels.IdsecPamshDeleteAccount{
			AccountID: accountID,
		})
		return pamshDeleteCleanupResult(t, "Account "+account.Name, delErr)
	})

	return account
}

// assertPamshMemberPermissionSet checks permission_set and permissions match the expected predefined set.
func assertPamshMemberPermissionSet(t *testing.T, member *safesmodels.IdsecPamshSafeMember, expectedSet string) {
	t.Helper()
	require.NotNil(t, member)
	assert.True(t, strings.EqualFold(expectedSet, member.PermissionSet),
		"expected permission_set %q, got %q", expectedSet, member.PermissionSet)
	expectedPerms, ok := pamshsafes.PermissionsForSet(expectedSet)
	require.True(t, ok, "unknown permission set %q", expectedSet)
	assert.True(t, reflect.DeepEqual(expectedPerms, member.Permissions),
		"permissions for %q do not match expected map", expectedSet)
}

// assertPamshMemberCustomPermissions checks permission_set is custom and permissions match exactly.
func assertPamshMemberCustomPermissions(t *testing.T, member *safesmodels.IdsecPamshSafeMember, expected safesmodels.IdsecPamshSafeMemberPermissions) {
	t.Helper()
	require.NotNil(t, member)
	assert.True(t, strings.EqualFold(safesmodels.Custom, member.PermissionSet),
		"expected permission_set custom, got %q", member.PermissionSet)
	assert.True(t, reflect.DeepEqual(expected, member.Permissions),
		"custom permissions do not match expected")
}

// pamshSafeMemberAddErrorSkippable reports whether an AddMember error should skip the test.
func pamshSafeMemberAddErrorSkippable(err error) (skip bool, reason string) {
	if err == nil {
		return false, ""
	}
	errMsg := err.Error()
	low := strings.ToLower(errMsg)
	if strings.Contains(low, "not found") || strings.Contains(low, "does not exist") {
		return true, "member does not exist in environment"
	}
	if strings.Contains(low, "forbidden") || strings.Contains(low, "not authorized") ||
		strings.Contains(low, "insufficient") || strings.Contains(errMsg, "403") {
		return true, "insufficient privileges for permission set"
	}
	return false, ""
}

// trackPamshSafeMemberDelete registers DeleteMember cleanup (runs before safe delete in LIFO order).
func trackPamshSafeMemberDelete(t *testing.T, ctx *framework.TestContext, safesSvc *pamshsafes.IdsecPamshSafesService, safeID, memberName string) {
	t.Helper()

	ctx.TrackResourceByType("SafeMember", memberName, func() error {
		t.Logf("Cleaning up safe member: %s", memberName)
		delErr := safesSvc.DeleteMember(&safesmodels.IdsecPamshDeleteSafeMember{
			SafeID:     safeID,
			MemberName: memberName,
		})
		return pamshDeleteCleanupResult(t, "SafeMember "+memberName, delErr)
	})
}
