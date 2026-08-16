package accounts_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
)

func TestAccountsGetComplianceInfo_happyPath(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/rotation/accounts/123_4/compliance-info" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{
			"accountState": "PLATFORM_DELETED",
			"disableReason": null,
			"resumeActionEnabled": null,
			"platformId": "AmirWindowsDesktopLocalAccounts",
			"accountGroupId": null,
			"accountGroupName": null,
			"groupPlatformId": null,
			"managementType": null,
			"lastMessages": [],
			"actionInProgress": null,
			"lastAction": {
				"username": "CyberarkRotationService",
				"type": "ADDED",
				"time": "2026-06-09T09:47:05.727000Z"
			},
			"lastVerifyAction": {
				"username": "CyberarkRotationService",
				"type": "ADDED",
				"time": "2026-06-09T09:47:05.727000Z"
			},
			"change": {
				"compliant": "UNKNOWN",
				"policyInterval": 0,
				"lastSuccess": null,
				"nextSchedule": null,
				"retryCount": 0,
				"daysSinceLastSuccess": 44,
				"secondsSinceLastSuccess": 3818117,
				"username": "System",
				"actionEnabled": false,
				"actionDisabledReason": "MISSING_PERMISSIONS",
				"actionEnabledVault": false,
				"allowSpecifySecret": false,
				"enforcePasswordPolicyOnManualChange": true
			},
			"verify": {
				"compliant": "UNKNOWN",
				"policyInterval": 0,
				"lastSuccess": null,
				"nextSchedule": null,
				"retryCount": 0,
				"daysSinceLastSuccess": 44,
				"secondsSinceLastSuccess": 3818117,
				"username": "System",
				"actionEnabled": false,
				"actionDisabledReason": "MISSING_PERMISSIONS"
			},
			"reconcile": {
				"actionEnabled": false,
				"actionDisabledReason": "MISSING_PERMISSIONS",
				"nextSchedule": null,
				"retryCount": 0
			},
			"delete": {
				"nextSchedule": null,
				"username": null,
				"retryCount": 0
			},
			"activeJob": null,
			"isActiveWorkflowSession": false,
			"releaseAccountEnabled": false,
			"unlockAccountEnabled": false,
			"createdAt": "2026-06-09T09:47:05.707000Z"
		}`)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	complianceInfo, err := svc.GetComplianceInfo(&accountsmodels.IdsecPCloudGetAccountComplianceInfo{AccountID: "123_4"})
	require.NoError(t, err)
	require.Equal(t, "PLATFORM_DELETED", complianceInfo.AccountState)
	require.Equal(t, "AmirWindowsDesktopLocalAccounts", complianceInfo.PlatformID)
	require.False(t, complianceInfo.IsActiveWorkflowSession)
	require.Equal(t, "2026-06-09T09:47:05.707000Z", complianceInfo.CreatedAt)

	require.NotNil(t, complianceInfo.LastAction)
	require.Equal(t, "CyberarkRotationService", complianceInfo.LastAction.Username)
	require.Equal(t, "ADDED", complianceInfo.LastAction.Type)

	require.NotNil(t, complianceInfo.Change)
	require.Equal(t, "UNKNOWN", complianceInfo.Change.Compliant)
	require.Equal(t, 44, complianceInfo.Change.DaysSinceLastSuccess)
	require.Equal(t, 3818117, complianceInfo.Change.SecondsSinceLastSuccess)
	require.Equal(t, "MISSING_PERMISSIONS", complianceInfo.Change.ActionDisabledReason)
	require.True(t, complianceInfo.Change.EnforcePasswordPolicyOnManualChange)

	require.NotNil(t, complianceInfo.Verify)
	require.Equal(t, "MISSING_PERMISSIONS", complianceInfo.Verify.ActionDisabledReason)

	require.NotNil(t, complianceInfo.Reconcile)
	require.False(t, complianceInfo.Reconcile.ActionEnabled)

	require.NotNil(t, complianceInfo.Delete)
	require.Equal(t, 0, complianceInfo.Delete.RetryCount)
}

func TestAccountsGetComplianceInfo_httpError(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"account not found"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	complianceInfo, err := svc.GetComplianceInfo(&accountsmodels.IdsecPCloudGetAccountComplianceInfo{AccountID: "missing"})
	require.Error(t, err)
	require.Nil(t, complianceInfo)
}
