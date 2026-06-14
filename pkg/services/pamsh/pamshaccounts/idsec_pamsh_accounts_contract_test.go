package pamshaccounts

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/internal"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"
)

func TestCreate_outbound_request_contract(t *testing.T) {
	t.Parallel()

	var payload map[string]interface{}

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts") {
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			req.Body = io.NopCloser(bytes.NewReader(body))
			require.NoError(t, json.Unmarshal(body, &payload))
			return createdAccountResponse(req, "aid-contract", "contract-account")
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	_, err := svc.Create(&accountsmodels.IdsecPamshAddAccount{
		Name:       "contract-account",
		SafeName:   "safe-1",
		PlatformID: "platform-1",
		Username:   "user1",
		Address:    "10.0.0.1",
		Secret:     "secret-value",
		SecretManagement: &accountsmodels.IdsecPamshAccountSecretManagement{
			AutomaticManagementEnabled: true,
			ManualManagementReason:     "manual-reason",
			LastModifiedTime:           12345,
		},
	})
	require.NoError(t, err)

	require.Equal(t, "contract-account", payload["name"])
	require.Equal(t, "safe-1", payload["safeName"])
	require.Equal(t, "platform-1", payload["platformId"])
	require.Equal(t, "user1", payload["username"])
	require.Equal(t, "10.0.0.1", payload["address"])
	require.Equal(t, "secret-value", payload["secret"])

	secretManagement, ok := payload["secretManagement"].(map[string]interface{})
	require.True(t, ok, "expected secretManagement object in POST body")
	require.Equal(t, true, secretManagement["automaticManagementEnabled"])
	require.Equal(t, "manual-reason", secretManagement["manualManagementReason"])
	require.EqualValues(t, 12345, secretManagement["lastModifiedTime"])
}

func TestUpdate_outbound_patch_contract(t *testing.T) {
	t.Parallel()

	const accountID = "aid-patch-contract"
	var operations []map[string]interface{}

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPatch && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/"+accountID) {
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			req.Body = io.NopCloser(bytes.NewReader(body))
			require.NoError(t, json.Unmarshal(body, &operations))
			return accountOKResponse(req, accountID, "patch-contract")
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	_, err := svc.Update(&accountsmodels.IdsecPamshUpdateAccount{
		AccountID: accountID,
		Name:      "updated-name",
		Address:   "10.0.0.2",
		SecretManagement: &accountsmodels.IdsecPamshAccountSecretManagement{
			AutomaticManagementEnabled: true,
			ManualManagementReason:     "reason",
			LastModifiedTime:           99,
		},
	})
	require.NoError(t, err)

	paths := patchPaths(operations)
	require.Contains(t, paths, "name")
	require.Contains(t, paths, "address")
	require.Contains(t, paths, "secretManagement/automaticManagementEnabled")
	require.Contains(t, paths, "secretManagement/manualManagementReason")
	require.NotContains(t, paths, "secretManagement/lastModifiedTime")

	for _, op := range operations {
		require.Equal(t, "replace", op["op"])
		path, _ := op["path"].(string)
		require.True(t, strings.HasPrefix(path, "/"), "patch path must be absolute: %s", path)
	}
}
