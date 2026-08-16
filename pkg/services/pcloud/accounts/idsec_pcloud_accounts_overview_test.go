package accounts_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
)

func TestAccountsGetOverview_happyPath(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/PasswordVault/api/ExtendedAccounts/584_3/overview" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{
			"Compliance": {
				"IsCompliant": true,
				"LastModifiedDate": 1780998416,
				"LastModifiedBy": "ayelletux@cyberark.cloud.17822",
				"ModificationType": "Change"
			},
			"Activities": [
				{
					"Alert": false,
					"Date": 1780998421,
					"User": "CyberarkAccountsIntegration",
					"Action": "Retrieve password",
					"ActionID": 295,
					"ClientID": "PVWA",
					"MoreInfo": "",
					"Reason": "Internal Retrieve"
				},
				{
					"Alert": false,
					"Date": 1780998417,
					"User": "ayelletux@cyberark.cloud.17822",
					"Action": "Add File Category",
					"ActionID": 105,
					"ClientID": "PVWA",
					"MoreInfo": "CreationMethod",
					"Reason": "Value=[PVWA]"
				}
			],
			"TotalDependencies": null,
			"FailedDependencies": null,
			"Recordings": null,
			"Details": {
				"LastVerifiedDate": 0,
				"LastVerifiedBy": null,
				"LastUsedBy": "CyberarkAccountsIntegration",
				"LastUsedDate": 1780998421,
				"CreationDate": 1780998416,
				"Name": "Operating System-AmirWindowsDesktopLocalAccounts-1.1.1.1-rubiru",
				"CreatedTime": 1780998416,
				"AccountURL": null,
				"ManagedByCPM": false,
				"CPMDisabled": "",
				"CPMStatus": null,
				"CPMErrorDetails": "",
				"ImmediateCPMTask": null,
				"DeletedBy": "",
				"DeletionDate": 0,
				"LockedBy": "",
				"IsFavorite": false,
				"IsNew": false,
				"SafeName": "aassa",
				"IsGroupMember": false,
				"DualControlStatus": "RequestNotNeeded",
				"RequiredProperties": null,
				"OptionalProperties": null,
				"LimitDomainAccess": null,
				"AccessDomainList": null,
				"RequestId": -1,
				"FutureTimeFrame": false,
				"LinkedAccounts": null
			},
			"Platform": null,
			"AvailableTabs": [
				"Activities"
			],
			"ActionsToDisplay": null,
			"EnabledActions": null
		}`)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	overview, err := svc.GetOverview(&accountsmodels.IdsecPCloudGetAccountOverview{AccountID: "584_3"})
	require.NoError(t, err)

	require.NotNil(t, overview.Compliance)
	require.True(t, overview.Compliance.IsCompliant)
	require.Equal(t, 1780998416, overview.Compliance.LastModifiedDate)
	require.Equal(t, "ayelletux@cyberark.cloud.17822", overview.Compliance.LastModifiedBy)
	require.Equal(t, "Change", overview.Compliance.ModificationType)

	require.Len(t, overview.Activities, 2)
	require.Equal(t, "CyberarkAccountsIntegration", overview.Activities[0].User)
	require.Equal(t, 295, overview.Activities[0].ActionID)
	require.Equal(t, "PVWA", overview.Activities[0].ClientID)

	require.NotNil(t, overview.Details)
	require.Equal(t, "CyberarkAccountsIntegration", overview.Details.LastUsedBy)
	require.Equal(t, 1780998421, overview.Details.LastUsedDate)
	require.Equal(t, "Operating System-AmirWindowsDesktopLocalAccounts-1.1.1.1-rubiru", overview.Details.Name)
	require.Equal(t, "aassa", overview.Details.SafeName)
	require.Equal(t, "RequestNotNeeded", overview.Details.DualControlStatus)
	require.Equal(t, -1, overview.Details.RequestID)
	require.False(t, overview.Details.ManagedByCPM)

	require.Equal(t, []string{"Activities"}, overview.AvailableTabs)
}

func TestAccountsGetOverview_httpError(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"account not found"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	overview, err := svc.GetOverview(&accountsmodels.IdsecPCloudGetAccountOverview{AccountID: "missing"})
	require.Error(t, err)
	require.Nil(t, overview)
}
