package accounts_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
)

// List error-propagation and pagination regression tests (minimal set):
//   - mid-pagination HTTP error after a good first page -> returned error, no channel;
//   - first request fails -> returned error, no channel;
//   - two OK pages -> single combined page with items from both requests, no error.

func newTestPCloudAccountsService(parts *pcloudint.MockISPServiceParts) *accounts.IdsecPCloudAccountsService {
	return &accounts.IdsecPCloudAccountsService{
		IdsecBaseService:    parts.BaseService,
		IdsecISPBaseService: parts.ISPBase,
	}
}

func TestAccountsList_midPaginationHTTPError_returnsErr(t *testing.T) {
	t.Parallel()
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/PasswordVault/api/accounts" {
			http.NotFound(w, r)
			return
		}
		listGETs++
		n := listGETs
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			next := "http://" + r.Host + "/PasswordVault/api/accounts?page=2"
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"value":[{"id":"a1","name":"n1","user_name":"u1","safe_name":"S1"}],"nextLink":%q}`, next)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"second page failed"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	ch, err := newTestPCloudAccountsService(parts).ListBy(&accountsmodels.IdsecPCloudAccountsFilter{})
	require.Error(t, err)
	require.Nil(t, ch)
	require.GreaterOrEqual(t, listGETs, 2,
		"pagination must issue a second GET when the API returns nextLink (decoded map key is next_link)")
}

func TestAccountsList_channelPropagatesFirstPageFailure(t *testing.T) {
	t.Parallel()
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/PasswordVault/api/accounts" {
			http.NotFound(w, r)
			return
		}
		listGETs++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"auth"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	ch, err := newTestPCloudAccountsService(parts).ListBy(&accountsmodels.IdsecPCloudAccountsFilter{})
	require.Error(t, err, "first and only page must surface as a returned error")
	require.Nil(t, ch)
	require.Equal(t, 1, listGETs, "only the first list GET before failure")
}

// TestAccountsListContext_cancelStopsPagination verifies that cancelling ctx while pagination is
// in flight against an endpoint that advertises another page forever unblocks the call (via the
// underlying HTTP request failing with context.Canceled) instead of hanging indefinitely.
func TestAccountsListContext_cancelStopsPagination(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/PasswordVault/api/accounts" {
			http.NotFound(w, r)
			return
		}
		next := "http://" + r.Host + "/PasswordVault/api/accounts?page=next"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"a1","name":"n1","user_name":"u1","safe_name":"S1"}],"nextLink":%q}`, next)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := newTestPCloudAccountsService(parts).ListByContext(ctx, &accountsmodels.IdsecPCloudAccountsFilter{})
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err, "cancelled pagination must surface an error instead of an empty success")
	case <-time.After(3 * time.Second):
		t.Fatal("ListByContext did not return after context cancellation (possible hang)")
	}
}

func TestAccountsList_happyMultiPageCombinedIntoSinglePage(t *testing.T) {
	t.Parallel()
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/PasswordVault/api/accounts" {
			http.NotFound(w, r)
			return
		}
		listGETs++
		n := listGETs
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			next := "http://" + r.Host + "/PasswordVault/api/accounts?page=2"
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"value":[{"id":"a1","name":"n1","user_name":"u1","safe_name":"S1"}],"nextLink":%q}`, next)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"a2","name":"n2","user_name":"u2","safe_name":"S2"}]}`)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	ch, err := newTestPCloudAccountsService(parts).ListBy(&accountsmodels.IdsecPCloudAccountsFilter{})
	require.NoError(t, err)
	require.Equal(t, 2, listGETs)

	var pages []*accounts.IdsecPCloudAccountsPage
	for p := range ch {
		pages = append(pages, p)
	}
	require.Len(t, pages, 1, "ListAllPaginated collapses all pages into a single page")
	require.Len(t, pages[0].Items, 2)
	require.Equal(t, "a1", pages[0].Items[0].AccountID)
	require.Equal(t, "a2", pages[0].Items[1].AccountID)
}

// TestAccountsListBy_appliesAllQueryParams verifies that a fully populated filter maps each field to
// the correct outgoing query-param key/value. In particular SafeName must become the OData-style
// filter "safeName eq <value>" and not a "safe_name" param.
func TestAccountsListBy_appliesAllQueryParams(t *testing.T) {
	t.Parallel()
	var gotQuery url.Values
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/PasswordVault/api/accounts" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"a1","name":"n1","user_name":"u1","safe_name":"S1"}]}`)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	ch, err := newTestPCloudAccountsService(parts).ListBy(&accountsmodels.IdsecPCloudAccountsFilter{
		Search:     "admin",
		SearchType: "contains",
		Sort:       "userName desc",
		SafeName:   "MySafe",
		Offset:     5,
		Limit:      50,
	})
	require.NoError(t, err)
	require.NotNil(t, ch)
	for range ch {
	}

	require.Equal(t, "admin", gotQuery.Get("search"))
	require.Equal(t, "contains", gotQuery.Get("searchType"))
	require.Equal(t, "userName desc", gotQuery.Get("sort"))
	require.Equal(t, "5", gotQuery.Get("offset"))
	require.Equal(t, "50", gotQuery.Get("limit"))
	require.Equal(t, "safeName eq MySafe", gotQuery.Get("filter"))
}
