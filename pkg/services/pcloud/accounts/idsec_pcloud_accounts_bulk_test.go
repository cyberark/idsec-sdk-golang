package accounts_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
)

// bulkAccountsHandler routes the compliance-info, overview, and activities endpoints for a set of account IDs.
// Any account ID containing "missing" responds with 404 so per-account error handling can be exercised.
func bulkAccountsHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		path := r.URL.Path
		if strings.Contains(path, "missing") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"account not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(path, "/api/rotation/accounts/") && strings.HasSuffix(path, "/compliance-info"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"accountState":"PLATFORM_DELETED","platformId":"AmirWindowsDesktopLocalAccounts"}`)
		case strings.HasPrefix(path, "/PasswordVault/api/ExtendedAccounts/") && strings.HasSuffix(path, "/overview"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Compliance":{"IsCompliant":true},"AvailableTabs":["Activities"]}`)
		case strings.HasPrefix(path, "/api/accounts/") && strings.HasSuffix(path, "/activities"):
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{"Activities":[{"User":"John Doe","Action":"Retrieve password","ActionID":295}],"Total":1}`)
		case strings.HasPrefix(path, "/PasswordVault/api/accounts/") && strings.HasSuffix(path, "/"):
			accountID := strings.TrimSuffix(strings.TrimPrefix(path, "/PasswordVault/api/accounts/"), "/")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"id":%q,"safeName":"BulkTestSafe"}`, accountID)
		default:
			http.NotFound(w, r)
		}
	})
}

func TestAccountsBulkGetComplianceInfo_mixedResultsPreserveOrder(t *testing.T) {
	t.Parallel()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, bulkAccountsHandler(t))
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	results, err := svc.BulkGetComplianceInfo(&accountsmodels.IdsecPCloudBulkGetAccountComplianceInfo{
		AccountIDs:     []string{"1_1", "missing_2", "3_3"},
		MaxConcurrency: 2,
	})
	require.NoError(t, err)
	require.Len(t, results, 3)

	require.Equal(t, "1_1", results[0].AccountID)
	require.Empty(t, results[0].Error)
	require.NotNil(t, results[0].ComplianceInfo)
	require.Equal(t, "PLATFORM_DELETED", results[0].ComplianceInfo.AccountState)

	require.Equal(t, "missing_2", results[1].AccountID)
	require.NotEmpty(t, results[1].Error)
	require.Nil(t, results[1].ComplianceInfo)

	require.Equal(t, "3_3", results[2].AccountID)
	require.Empty(t, results[2].Error)
	require.NotNil(t, results[2].ComplianceInfo)
}

func TestAccountsBulkGetOverview_happyPath(t *testing.T) {
	t.Parallel()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, bulkAccountsHandler(t))
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	results, err := svc.BulkGetOverview(&accountsmodels.IdsecPCloudBulkGetAccountOverview{
		AccountIDs: []string{"584_3", "584_4"},
	})
	require.NoError(t, err)
	require.Len(t, results, 2)
	for _, result := range results {
		require.Empty(t, result.Error)
		require.NotNil(t, result.Overview)
		require.NotNil(t, result.Overview.Compliance)
		require.True(t, result.Overview.Compliance.IsCompliant)
		require.Equal(t, []string{"Activities"}, result.Overview.AvailableTabs)
	}
}

func TestAccountsBulkListActivities_happyPath(t *testing.T) {
	t.Parallel()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, bulkAccountsHandler(t))
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	results, err := svc.BulkListActivities(&accountsmodels.IdsecPCloudBulkListAccountActivities{
		AccountIDs: []string{"1_1", "2_2", "3_3"},
	})
	require.NoError(t, err)
	require.Len(t, results, 3)
	for _, result := range results {
		require.Empty(t, result.Error)
		require.Len(t, result.Activities, 1)
		require.Equal(t, "John Doe", result.Activities[0].User)
		require.Equal(t, 295, result.Activities[0].ActionID)
	}
}

func TestAccountsBulkGetComplianceInfo_noAccountIDs(t *testing.T) {
	t.Parallel()
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, bulkAccountsHandler(t))
	t.Cleanup(cleanup)

	svc := newTestPCloudAccountsService(parts)
	results, err := svc.BulkGetComplianceInfo(&accountsmodels.IdsecPCloudBulkGetAccountComplianceInfo{})
	require.Error(t, err)
	require.Nil(t, results)
}
