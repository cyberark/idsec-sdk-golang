package accounts_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
)

type fakeAccount struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	UserName string `json:"user_name"`
	Address  string `json:"address"`
	SafeName string `json:"safe_name"`
}

// fakePVWA mimics Privilege Cloud's default WideAccountsSearch=No: the search keyword matches
// account properties (username, address) but never the account name. It honors
// filter=safeName eq X and pages one item at a time.
func fakePVWA(t *testing.T, accounts []fakeAccount) (http.Handler, func() []map[string]string) {
	var mu sync.Mutex
	var listQueries []map[string]string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/PasswordVault/api/accounts" {
			q := map[string]string{}
			for k := range r.URL.Query() {
				q[k] = r.URL.Query().Get(k)
			}
			mu.Lock()
			listQueries = append(listQueries, q)
			mu.Unlock()
			var matched []fakeAccount
			for _, a := range accounts {
				if s := q["search"]; s != "" && !strings.Contains(a.UserName, s) && !strings.Contains(a.Address, s) {
					continue
				}
				if f := q["filter"]; f != "" && f != "safeName eq "+a.SafeName {
					continue
				}
				matched = append(matched, a)
			}
			offset, _ := strconv.Atoi(q["offset"])
			body := map[string]interface{}{"value": []fakeAccount{}}
			if offset < len(matched) {
				body["value"] = matched[offset : offset+1]
				if offset+1 < len(matched) {
					next := url.Values{"limit": {"1"}, "offset": {strconv.Itoa(offset + 1)}}
					for _, k := range []string{"search", "filter"} {
						if q[k] != "" {
							next.Set(k, q[k])
						}
					}
					body["nextLink"] = "api/accounts?" + next.Encode()
				}
			}
			assert.NoError(t, json.NewEncoder(w).Encode(body))
			return
		}
		for _, a := range accounts {
			if r.URL.Path == "/PasswordVault/api/accounts/"+a.ID+"/" {
				assert.NoError(t, json.NewEncoder(w).Encode(a))
				return
			}
		}
		http.NotFound(w, r)
	})
	return h, func() []map[string]string {
		mu.Lock()
		defer mu.Unlock()
		return listQueries
	}
}

func newFakeAccountsService(t *testing.T, h http.Handler) *accounts.IdsecPCloudAccountsService {
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)
	return newTestPCloudAccountsService(parts)
}

var sharedNameAccounts = []fakeAccount{
	{ID: "1_1", Name: "other", UserName: "root", Address: "host1", SafeName: "SafeA"},
	{ID: "1_2", Name: "sv-admin", UserName: "administrator", Address: "say-vandelay.com", SafeName: "SafeA"},
	{ID: "2_1", Name: "sv-admin", UserName: "administrator", Address: "other.com", SafeName: "SafeB"},
}

// Account names are not searchable, so Get by name falls back to listing and returns the first match.
func TestGet_byName_nameNotSearchable_fallsBackToListing(t *testing.T) {
	t.Parallel()
	h, _ := fakePVWA(t, sharedNameAccounts)
	svc := newFakeAccountsService(t, h)

	got, err := svc.Get(&accountsmodels.IdsecPCloudGetAccount{AccountName: "sv-admin"})
	require.NoError(t, err)
	require.Equal(t, "1_2", got.AccountID)
}

func TestGetByName_withSafe_filtersBySafe(t *testing.T) {
	t.Parallel()
	h, queries := fakePVWA(t, sharedNameAccounts)
	svc := newFakeAccountsService(t, h)

	got, err := svc.GetByName(&accountsmodels.IdsecPCloudGetAccountByName{AccountName: "sv-admin", SafeName: "SafeB"})
	require.NoError(t, err)
	require.Equal(t, "2_1", got.AccountID)
	for _, q := range queries() {
		require.Equal(t, "safeName eq SafeB", q["filter"])
	}
}

func TestGet_byName_searchHit_skipsFallback(t *testing.T) {
	t.Parallel()
	accounts := []fakeAccount{{ID: "3_1", Name: "host9_root", UserName: "host9_root", Address: "host9", SafeName: "SafeA"}}
	h, queries := fakePVWA(t, accounts)
	svc := newFakeAccountsService(t, h)

	got, err := svc.Get(&accountsmodels.IdsecPCloudGetAccount{AccountName: "host9_root"})
	require.NoError(t, err)
	require.Equal(t, "3_1", got.AccountID)
	require.Len(t, queries(), 1)
}

func TestGet_byName_missing_returnsNotFound(t *testing.T) {
	t.Parallel()
	h, _ := fakePVWA(t, sharedNameAccounts)
	svc := newFakeAccountsService(t, h)

	_, err := svc.Get(&accountsmodels.IdsecPCloudGetAccount{AccountName: "missing"})
	require.ErrorContains(t, err, "account with name [missing] not found")
}

func TestGet_byName_fallbackListError_isReturned(t *testing.T) {
	t.Parallel()
	fake, _ := fakePVWA(t, sharedNameAccounts)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path == "/PasswordVault/api/accounts" && q.Get("search") == "" && q.Get("offset") == "1" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fake.ServeHTTP(w, r)
	})
	svc := newFakeAccountsService(t, h)

	_, err := svc.Get(&accountsmodels.IdsecPCloudGetAccount{AccountName: "missing"})
	require.ErrorContains(t, err, "[500]")
	require.NotContains(t, err.Error(), "not found")
}

func TestCreate_conflict_returnsExistingAccountFromSameSafe(t *testing.T) {
	t.Parallel()
	fake, _ := fakePVWA(t, sharedNameAccounts)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/PasswordVault/api/accounts" {
			w.WriteHeader(http.StatusConflict)
			return
		}
		fake.ServeHTTP(w, r)
	})
	svc := newFakeAccountsService(t, h)

	got, err := svc.Create(&accountsmodels.IdsecPCloudAddAccount{
		Name: "sv-admin", SafeName: "SafeB", PlatformID: "WinDomain", Secret: "x",
	})
	require.NoError(t, err)
	require.Equal(t, "2_1", got.AccountID)
}
