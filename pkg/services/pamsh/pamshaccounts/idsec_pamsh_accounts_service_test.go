package pamshaccounts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/internal"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"
)

func newTestPamshAccountsService(parts *internal.MockPVWAServiceParts) *IdsecPamshAccountsService {
	return &IdsecPamshAccountsService{
		IdsecBaseService:     parts.BaseService,
		IdsecPVWABaseService: parts.PVWABase,
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCreate_conflictDrainsFirstResponseBeforeGet(t *testing.T) {
	t.Parallel()

	const accountName = "existing-account"
	var postBody *internal.TrackableBody

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts"):
			body := internal.NewTrackableBody(io.NopCloser(strings.NewReader(`{"message":"already exists"}`)))
			postBody = body
			return &http.Response{
				StatusCode: http.StatusConflict,
				Body:       body,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    req,
			}, nil
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts"):
			require.NotNil(t, postBody)
			require.True(t, postBody.Closed(), "conflict POST body must be closed before list/get for name resolution")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"value": [{"id": "aid-1", "name": %q, "user_name": "user1"}]
				}`, accountName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/aid-1"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"id": "aid-1",
					"name": %q,
					"user_name": "user1"
				}`, accountName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
				Request:    req,
			}, nil
		}
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Create(&accountsmodels.IdsecPamshAddAccount{
		Name:       accountName,
		SafeName:   "safe-1",
		PlatformID: "platform-1",
	})
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, accountName, account.Name)
}

func TestGet_resolvesAccountByName(t *testing.T) {
	t.Parallel()

	const accountName = "lookup-account"

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"value": [{"id": "aid-lookup", "name": %q, "user_name": "user1"}]
				}`, accountName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/aid-lookup"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"id": "aid-lookup",
					"name": %q,
					"user_name": "user1"
				}`, accountName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
				Request:    req,
			}, nil
		}
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Get(&accountsmodels.IdsecPamshGetAccount{AccountName: accountName})
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, "aid-lookup", account.AccountID)
	require.Equal(t, accountName, account.Name)
}

func TestCreate_parses_full_pvwa_response_contract(t *testing.T) {
	t.Parallel()

	const accountID = "6_24"

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts") {
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(strings.NewReader(fullPVWAResponseJSON(accountID, "acct"))),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    req,
			}, nil
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Create(&accountsmodels.IdsecPamshAddAccount{
		Name:       "acct",
		SafeName:   "MySafe",
		PlatformID: "platform-1",
	})
	require.NoError(t, err)
	assertFullPVWAAccountContract(t, account)
}

func TestUpdate_parses_full_pvwa_response_contract(t *testing.T) {
	t.Parallel()

	const accountID = "6_24"

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPatch && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/"+accountID) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(fullPVWAResponseJSON(accountID, "acct"))),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    req,
			}, nil
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Update(&accountsmodels.IdsecPamshUpdateAccount{
		AccountID: accountID,
		Name:      "acct",
	})
	require.NoError(t, err)
	assertFullPVWAAccountContract(t, account)
}

func TestCreate_success_returns_parsed_account(t *testing.T) {
	t.Parallel()

	const (
		accountID   = "aid-new"
		accountName = "new-account"
	)

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts") {
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"id": %q,
					"name": %q,
					"user_name": "user1",
					"safe_name": "safe-1"
				}`, accountID, accountName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Create(&accountsmodels.IdsecPamshAddAccount{
		Name:       accountName,
		SafeName:   "safe-1",
		PlatformID: "platform-1",
	})
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, accountID, account.AccountID)
	require.Equal(t, accountName, account.Name)
	require.Equal(t, "user1", account.Username)
}

func TestCreate_generates_name_when_empty(t *testing.T) {
	t.Parallel()

	const expectedName = "safe-1_platform-1_10.0.0.1_user1"
	var postedName string

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts") {
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			req.Body = io.NopCloser(bytes.NewReader(body))
			var payload map[string]interface{}
			require.NoError(t, json.Unmarshal(body, &payload))
			postedName, _ = payload["name"].(string)
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"id": "aid-generated",
					"name": %q,
					"user_name": "user1"
				}`, expectedName))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Create(&accountsmodels.IdsecPamshAddAccount{
		SafeName:   "safe-1",
		PlatformID: "platform-1",
		Address:    "10.0.0.1",
		Username:   "user1",
	})
	require.NoError(t, err)
	require.Equal(t, expectedName, postedName)
	require.Equal(t, expectedName, account.Name)
}

func TestCreate_includes_secret_management_in_payload(t *testing.T) {
	t.Parallel()

	var payload map[string]interface{}

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts") {
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			req.Body = io.NopCloser(bytes.NewReader(body))
			require.NoError(t, json.Unmarshal(body, &payload))
			return createdAccountResponse(req, "aid-opts", "opts-account")
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	_, err := svc.Create(&accountsmodels.IdsecPamshAddAccount{
		Name:     "opts-account",
		SafeName: "safe-1",
		SecretManagement: &accountsmodels.IdsecPamshAccountSecretManagement{
			AutomaticManagementEnabled: true,
			ManualManagementReason:     "manual-reason",
			LastModifiedTime:           12345,
		},
	})
	require.NoError(t, err)

	secretManagement, ok := payload["secretManagement"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, true, secretManagement["automaticManagementEnabled"])
	require.Equal(t, "manual-reason", secretManagement["manualManagementReason"])
	require.EqualValues(t, 12345, secretManagement["lastModifiedTime"])
}

func TestCreate_error_on_non_created_status(t *testing.T) {
	t.Parallel()

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts") {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(`{"errorCode":"bad request"}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    req,
			}, nil
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Create(&accountsmodels.IdsecPamshAddAccount{
		Name:     "bad-account",
		SafeName: "safe-1",
	})
	require.Error(t, err)
	require.Nil(t, account)
	require.Contains(t, err.Error(), "failed to add account")
	require.Contains(t, err.Error(), "400")
}

func TestCreate_conflict_retries_post_when_get_fails(t *testing.T) {
	t.Parallel()

	const accountName = "retry-account"
	var postCount atomic.Int32

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts"):
			n := postCount.Add(1)
			if n == 1 {
				return &http.Response{
					StatusCode: http.StatusConflict,
					Body:       io.NopCloser(strings.NewReader(`{"message":"already exists"}`)),
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Request:    req,
				}, nil
			}
			return createdAccountResponse(req, "aid-retry", accountName)
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/PasswordVault/API/Accounts"):
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"value": []}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    req,
			}, nil
		default:
			return notFoundResponse(req)
		}
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Create(&accountsmodels.IdsecPamshAddAccount{
		Name:     accountName,
		SafeName: "safe-1",
	})
	require.NoError(t, err)
	require.Equal(t, accountName, account.Name)
	require.Equal(t, int32(2), postCount.Load())
}

func TestUpdate_success_patch_returns_parsed_account(t *testing.T) {
	t.Parallel()

	const accountID = "aid-update"

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPatch && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/"+accountID) {
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			req.Body = io.NopCloser(bytes.NewReader(body))

			var operations []map[string]interface{}
			require.NoError(t, json.Unmarshal(body, &operations))
			require.NotEmpty(t, operations)
			require.Equal(t, "replace", operations[0]["op"])
			require.Equal(t, "/name", operations[0]["path"])

			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
					"id": %q,
					"name": "updated-name",
					"user_name": "user-updated"
				}`, accountID))),
				Header:  http.Header{"Content-Type": []string{"application/json"}},
				Request: req,
			}, nil
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Update(&accountsmodels.IdsecPamshUpdateAccount{
		AccountID: accountID,
		Name:      "updated-name",
	})
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, accountID, account.AccountID)
	require.Equal(t, "updated-name", account.Name)
	require.Equal(t, "user-updated", account.Username)
}

func TestUpdate_includes_secret_management_in_patch(t *testing.T) {
	t.Parallel()

	const accountID = "aid-patch-opts"
	var operations []map[string]interface{}

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPatch && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/"+accountID) {
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			req.Body = io.NopCloser(bytes.NewReader(body))
			require.NoError(t, json.Unmarshal(body, &operations))
			return accountOKResponse(req, accountID, "patch-opts")
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	_, err := svc.Update(&accountsmodels.IdsecPamshUpdateAccount{
		AccountID: accountID,
		SecretManagement: &accountsmodels.IdsecPamshAccountSecretManagement{
			AutomaticManagementEnabled: true,
			ManualManagementReason:     "reason",
			LastModifiedTime:           99,
		},
	})
	require.NoError(t, err)

	paths := patchPaths(operations)
	require.Contains(t, paths, "secretManagement/automaticManagementEnabled")
	require.Contains(t, paths, "secretManagement/manualManagementReason")
	require.NotContains(t, paths, "secretManagement/lastModifiedTime")
}

func TestUpdate_no_operations_fetches_existing_account(t *testing.T) {
	t.Parallel()

	const accountID = "aid-fetch-only"

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPatch:
			t.Fatal("unexpected PATCH when update has no patchable fields")
			return nil, nil
		case req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/"+accountID):
			return accountOKResponse(req, accountID, "fetch-only")
		default:
			return notFoundResponse(req)
		}
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Update(&accountsmodels.IdsecPamshUpdateAccount{AccountID: accountID})
	require.NoError(t, err)
	require.Equal(t, accountID, account.AccountID)
	require.Equal(t, "fetch-only", account.Name)
}

func TestUpdate_with_secret_updates_vault(t *testing.T) {
	t.Parallel()

	const accountID = "aid-secret-update"
	var passwordUpdateCalled bool

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPatch && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/"+accountID):
			return accountOKResponse(req, accountID, "secret-update")
		case req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/"+accountID+"/Password/Update"):
			passwordUpdateCalled = true
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			req.Body = io.NopCloser(bytes.NewReader(body))
			var payload map[string]interface{}
			require.NoError(t, json.Unmarshal(body, &payload))
			require.Equal(t, "new-password", payload["newCredentials"])
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    req,
			}, nil
		default:
			return notFoundResponse(req)
		}
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Update(&accountsmodels.IdsecPamshUpdateAccount{
		AccountID: accountID,
		Name:      "secret-update",
		Secret:    "new-password",
	})
	require.NoError(t, err)
	require.True(t, passwordUpdateCalled)
	require.Equal(t, accountID, account.AccountID)
}

func TestUpdate_error_on_patch_non_ok_status(t *testing.T) {
	t.Parallel()

	const accountID = "aid-patch-fail"

	parts := internal.SetupMockPVWAServicePartsWithTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPatch && strings.Contains(req.URL.Path, "/PasswordVault/API/Accounts/"+accountID) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(`{"errorCode":"invalid"}`)),
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Request:    req,
			}, nil
		}
		return notFoundResponse(req)
	}))
	svc := newTestPamshAccountsService(parts)

	account, err := svc.Update(&accountsmodels.IdsecPamshUpdateAccount{
		AccountID: accountID,
		Name:      "will-fail",
	})
	require.Error(t, err)
	require.Nil(t, account)
	require.Contains(t, err.Error(), "failed to update account")
	require.Contains(t, err.Error(), "400")
}

func notFoundResponse(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader(`{"error":"not found"}`)),
		Request:    req,
	}, nil
}

func createdAccountResponse(req *http.Request, accountID, accountName string) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusCreated,
		Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
			"id": %q,
			"name": %q,
			"user_name": "user1"
		}`, accountID, accountName))),
		Header:  http.Header{"Content-Type": []string{"application/json"}},
		Request: req,
	}, nil
}

func accountOKResponse(req *http.Request, accountID, accountName string) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{
			"id": %q,
			"name": %q,
			"user_name": "user1"
		}`, accountID, accountName))),
		Header:  http.Header{"Content-Type": []string{"application/json"}},
		Request: req,
	}, nil
}

func fullPVWAResponseJSON(accountID, accountName string) string {
	return fmt.Sprintf(`{
		"id": %q,
		"name": %q,
		"safeName": "MySafe",
		"userName": "admin",
		"secretManagement": {
			"automaticManagementEnabled": true,
			"manualManagementReason": "Reason text",
			"lastModifiedTime": 99
		}
	}`, accountID, accountName)
}

func assertFullPVWAAccountContract(t *testing.T, account *accountsmodels.IdsecPamshAccount) {
	t.Helper()
	require.NotNil(t, account)
	require.Equal(t, "6_24", account.AccountID)
	require.Equal(t, "acct", account.Name)
	require.Equal(t, "MySafe", account.SafeName)
	require.Equal(t, "admin", account.Username)
	require.NotNil(t, account.SecretManagement)
	require.True(t, account.SecretManagement.AutomaticManagementEnabled)
	require.Equal(t, "Reason text", account.SecretManagement.ManualManagementReason)
	require.Equal(t, 99, account.SecretManagement.LastModifiedTime)
}

func patchPaths(operations []map[string]interface{}) []string {
	paths := make([]string, 0, len(operations))
	for _, op := range operations {
		path, _ := op["path"].(string)
		path = strings.TrimPrefix(path, "/")
		paths = append(paths, path)
	}
	return paths
}

func patchReplaceValue(operations []map[string]interface{}, flatPath string) (interface{}, bool) {
	for _, op := range operations {
		path, _ := op["path"].(string)
		if strings.TrimPrefix(path, "/") == flatPath {
			return op["value"], true
		}
	}
	return nil, false
}
