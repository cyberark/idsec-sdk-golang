package accounts_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
)

func TestAccountsListActivities_happyPath(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/accounts/123_4/activities" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{
			"Activities": [
				{
					"Alert": false,
					"Date": 1698947376,
					"User": "John Doe",
					"Action": "Add File Category",
					"ActionID": 105,
					"ClientID": "XYZ",
					"MoreInfo": "CreationMethod",
					"Reason": "Value=[1234]"
				},
				{
					"Alert": false,
					"Date": 1698947376,
					"User": "Administrator",
					"Action": "Add File Category",
					"ActionID": 105,
					"ClientID": "PVWA",
					"MoreInfo": "UserName",
					"Reason": "Value=[2121]"
				}
			],
			"Total": 2
		}`)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	activities, err := svc.ListActivities(&accountsmodels.IdsecPCloudListAccountActivities{AccountID: "123_4"})
	require.NoError(t, err)
	require.Len(t, activities, 2)
	require.Equal(t, "John Doe", activities[0].User)
	require.Equal(t, 105, activities[0].ActionID)
	require.Equal(t, "XYZ", activities[0].ClientID)
	require.Equal(t, "CreationMethod", activities[0].MoreInfo)
	require.Equal(t, "Administrator", activities[1].User)
	require.Equal(t, "PVWA", activities[1].ClientID)
}

func TestAccountsListActivities_httpError(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"account not found"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	activities, err := svc.ListActivities(&accountsmodels.IdsecPCloudListAccountActivities{AccountID: "missing"})
	require.Error(t, err)
	require.Nil(t, activities)
}

func activitiesHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/accounts/123_4/activities" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{
			"Activities": [
				{
					"Alert": false,
					"Date": 1698947376,
					"User": "John Doe",
					"Action": "Add File Category",
					"ActionID": 105,
					"ClientID": "XYZ",
					"MoreInfo": "CreationMethod",
					"Reason": "Value=[1234]"
				},
				{
					"Alert": true,
					"Date": 1698947999,
					"User": "Administrator",
					"Action": "Remove File Category",
					"ActionID": 106,
					"ClientID": "PVWA",
					"MoreInfo": "UserName",
					"Reason": "Value=[2121]"
				}
			],
			"Total": 2
		}`)
	})
}

func TestAccountsListActivitiesBy_filtersByUser(t *testing.T) {
	t.Parallel()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, activitiesHandler(t))
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	activities, err := svc.ListActivitiesBy(&accountsmodels.IdsecPCloudAccountActivitiesFilter{
		AccountID: "123_4",
		User:      "Administrator",
	})
	require.NoError(t, err)
	require.Len(t, activities, 1)
	require.Equal(t, "Administrator", activities[0].User)
}

func TestAccountsListActivitiesBy_filtersByAlertsOnly(t *testing.T) {
	t.Parallel()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, activitiesHandler(t))
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	activities, err := svc.ListActivitiesBy(&accountsmodels.IdsecPCloudAccountActivitiesFilter{
		AccountID:  "123_4",
		AlertsOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, activities, 1)
	require.True(t, activities[0].Alert)
}

func TestAccountsListActivitiesBy_filtersByActionContainsAndDateRange(t *testing.T) {
	t.Parallel()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, activitiesHandler(t))
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	activities, err := svc.ListActivitiesBy(&accountsmodels.IdsecPCloudAccountActivitiesFilter{
		AccountID:      "123_4",
		ActionContains: "Add",
		FromDate:       1698947000,
		ToDate:         1698947500,
	})
	require.NoError(t, err)
	require.Len(t, activities, 1)
	require.Equal(t, "Add File Category", activities[0].Action)
}

func TestAccountsListActivitiesBy_noMatches(t *testing.T) {
	t.Parallel()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, activitiesHandler(t))
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	activities, err := svc.ListActivitiesBy(&accountsmodels.IdsecPCloudAccountActivitiesFilter{
		AccountID: "123_4",
		ClientID:  "does-not-exist",
	})
	require.NoError(t, err)
	require.Empty(t, activities)
}
