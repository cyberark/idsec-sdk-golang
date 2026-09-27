package accounts_test

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
)

// updateRequestCounts tallies the requests Update() issues against each endpoint it can call, so
// tests can assert exact counts rather than just "no error".
type updateRequestCounts struct {
	gets                int
	patches             int
	credentialPosts     int
	lastCredentialsBody string
}

// newUpdateTestHandler routes the three endpoints Update() can call for a single account ID:
// GET/PATCH on the account itself, and POST on the credentials-in-vault endpoint.
func newUpdateTestHandler(t *testing.T, accountID string, counts *updateRequestCounts) http.HandlerFunc {
	t.Helper()
	accountPath := fmt.Sprintf("/PasswordVault/api/accounts/%s/", accountID)
	credentialsPath := fmt.Sprintf("/PasswordVault/api/accounts/%s/password/update", accountID)
	accountResponse := fmt.Sprintf(`{"id":%q,"name":"test-account","safe_name":"test-safe","user_name":"test-user"}`, accountID)

	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == accountPath:
			counts.gets++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, accountResponse)
		case r.Method == http.MethodPatch && r.URL.Path == accountPath:
			counts.patches++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, accountResponse)
		case r.Method == http.MethodPost && r.URL.Path == credentialsPath:
			counts.credentialPosts++
			body, _ := io.ReadAll(r.Body)
			counts.lastCredentialsBody = string(body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}
}

// TestUpdate_SecretNilIssuesNoCredentialsRequest is the httptest-level counterpart to the
// resolveUpdateSecret table test: Secret == nil must not touch the credentials-in-vault endpoint,
// even though another field is changing and a PATCH is issued.
func TestUpdate_SecretNilIssuesNoCredentialsRequest(t *testing.T) {
	t.Parallel()
	counts := &updateRequestCounts{}
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, newUpdateTestHandler(t, "account-1", counts))
	t.Cleanup(cleanup)

	_, err := newTestPCloudAccountsService(parts).Update(&accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
		Address:   common.Ptr("10.0.0.1"),
	})
	require.NoError(t, err)

	require.Equal(t, 1, counts.patches, "one PATCH for the changed field")
	require.Equal(t, 0, counts.credentialPosts, "Secret == nil must not call the credentials endpoint")
}

// TestUpdate_SecretEmptyStringIssuesNoCredentialsRequest proves Secret == &"" is treated the same
// as "not supplied" at the Update() level, not as "blank the credential".
func TestUpdate_SecretEmptyStringIssuesNoCredentialsRequest(t *testing.T) {
	t.Parallel()
	counts := &updateRequestCounts{}
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, newUpdateTestHandler(t, "account-1", counts))
	t.Cleanup(cleanup)

	_, err := newTestPCloudAccountsService(parts).Update(&accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
		Address:   common.Ptr("10.0.0.1"),
		Secret:    common.Ptr(""),
	})
	require.NoError(t, err)

	require.Equal(t, 1, counts.patches, "one PATCH for the changed field")
	require.Equal(t, 0, counts.credentialPosts, `Secret == &"" must not call the credentials endpoint`)
}

// TestUpdate_SecretFileReadsFileAndIssuesExactlyOneCredentialsRequest proves that SecretFile with
// Secret nil reads the file and rotates the credential exactly once.
func TestUpdate_SecretFileReadsFileAndIssuesExactlyOneCredentialsRequest(t *testing.T) {
	t.Parallel()
	secretFile := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("file-secret-content"), 0o600))

	counts := &updateRequestCounts{}
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, newUpdateTestHandler(t, "account-1", counts))
	t.Cleanup(cleanup)

	_, err := newTestPCloudAccountsService(parts).Update(&accountsmodels.IdsecPCloudUpdateAccount{
		AccountID:  "account-1",
		SecretFile: common.Ptr(secretFile),
	})
	require.NoError(t, err)

	require.Equal(t, 1, counts.credentialPosts, "SecretFile with Secret nil must issue exactly one credentials request")
	require.Contains(t, counts.lastCredentialsBody, "file-secret-content", "the credentials request must carry the file's contents")
}

// TestUpdate_ZeroOperationsFallsBackToGet proves that an update struct with every pointer nil
// (nothing for the caller to change) issues no PATCH and falls back to Get.
func TestUpdate_ZeroOperationsFallsBackToGet(t *testing.T) {
	t.Parallel()
	counts := &updateRequestCounts{}
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, newUpdateTestHandler(t, "account-1", counts))
	t.Cleanup(cleanup)

	account, err := newTestPCloudAccountsService(parts).Update(&accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
	})
	require.NoError(t, err)
	require.NotNil(t, account)

	require.Equal(t, 1, counts.gets, "zero operations must fall back to exactly one Get")
	require.Equal(t, 0, counts.patches, "zero operations must not issue a PATCH")
	require.Equal(t, 0, counts.credentialPosts, "no secret was supplied, so no credentials request either")
}
