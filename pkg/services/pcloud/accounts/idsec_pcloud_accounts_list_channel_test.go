package accounts_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
)

// List channel regression tests (minimal set):
//   - mid-pagination HTTP error after a good first page → terminal page with Err (not silent close);
//   - first request fails → single terminal Err page (not confused with empty list);
//   - two OK pages → no Err on any page (next_link success path).

// requireProducerExits drains ch until it is closed, failing if that does not happen promptly
// (which would indicate the producer goroutine is leaked, blocked forever on a send).
func requireProducerExits[T any](t *testing.T, ch <-chan T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("producer goroutine did not exit after context cancellation (leak)")
	}
}

func newTestPCloudAccountsService(parts *pcloudint.MockISPServiceParts) *accounts.IdsecPCloudAccountsService {
	return &accounts.IdsecPCloudAccountsService{
		IdsecBaseService:    parts.BaseService,
		IdsecISPBaseService: parts.ISPBase,
	}
}

func drainAccountsListPages(t *testing.T, svc *accounts.IdsecPCloudAccountsService) []*accounts.IdsecPCloudAccountsPage {
	t.Helper()
	ch, err := svc.ListBy(&accountsmodels.IdsecPCloudAccountsFilter{})
	require.NoError(t, err)
	var pages []*accounts.IdsecPCloudAccountsPage
	for p := range ch {
		pages = append(pages, p)
	}
	return pages
}

func requireAccountsListPropagatesPage2Failure(t *testing.T, listGETs int, pages []*accounts.IdsecPCloudAccountsPage) {
	t.Helper()
	require.GreaterOrEqual(t, listGETs, 2,
		"pagination must issue a second GET when the API returns nextLink (decoded map key is next_link)")
	require.GreaterOrEqual(t, len(pages), 2, "expect at least one data page and a terminal error page")
	require.NoError(t, pages[0].Err, "data pages must not set Err")
	require.Error(t, pages[len(pages)-1].Err, "last page must carry Err after a page-2+ failure")
}

func TestAccountsList_midPaginationHTTPError_emitsTerminalErrPage(t *testing.T) {
	t.Parallel()
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/accounts" {
			http.NotFound(w, r)
			return
		}
		listGETs++
		n := listGETs
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			next := "http://" + r.Host + "/api/accounts?page=2"
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"value":[{"id":"a1","name":"n1","user_name":"u1","safe_name":"S1"}],"nextLink":%q}`, next)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"second page failed"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	pages := drainAccountsListPages(t, newTestPCloudAccountsService(parts))
	requireAccountsListPropagatesPage2Failure(t, listGETs, pages)
}

func TestAccountsList_channelPropagatesFirstPageFailure(t *testing.T) {
	t.Parallel()
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/accounts" {
			http.NotFound(w, r)
			return
		}
		listGETs++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"auth"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	pages := drainAccountsListPages(t, newTestPCloudAccountsService(parts))
	require.Equal(t, 1, listGETs, "only the first list GET before failure")
	require.Len(t, pages, 1, "terminal error page only, not silent empty channel")
	require.Error(t, pages[0].Err, "first and only page must carry Err")
}

// TestAccountsListContext_cancelReleasesProducer verifies the goroutine-leak fix: a consumer
// that abandons iteration early and cancels the context must release the producer goroutine,
// even though the API advertises another page forever.
func TestAccountsListContext_cancelReleasesProducer(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/accounts" {
			http.NotFound(w, r)
			return
		}
		next := "http://" + r.Host + "/api/accounts?page=next"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"a1","name":"n1","user_name":"u1","safe_name":"S1"}],"nextLink":%q}`, next)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := newTestPCloudAccountsService(parts).ListByContext(ctx, &accountsmodels.IdsecPCloudAccountsFilter{})
	require.NoError(t, err)

	first, ok := <-ch
	require.True(t, ok, "expected at least one page before abandoning iteration")
	require.NoError(t, first.Err)

	cancel()
	requireProducerExits(t, ch)
}

func TestAccountsList_happyMultiPageNoTerminalErr(t *testing.T) {
	t.Parallel()
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/accounts" {
			http.NotFound(w, r)
			return
		}
		listGETs++
		n := listGETs
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			next := "http://" + r.Host + "/api/accounts?page=2"
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"value":[{"id":"a1","name":"n1","user_name":"u1","safe_name":"S1"}],"nextLink":%q}`, next)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"a2","name":"n2","user_name":"u2","safe_name":"S2"}]}`)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	pages := drainAccountsListPages(t, newTestPCloudAccountsService(parts))
	require.Equal(t, 2, listGETs)
	require.Len(t, pages, 2)
	for i, p := range pages {
		require.NoError(t, p.Err, "page %d must not be a terminal error page on full success", i)
	}
	require.Len(t, pages[0].Items, 1)
	require.Len(t, pages[1].Items, 1)
	require.Equal(t, "a1", pages[0].Items[0].AccountID)
	require.Equal(t, "a2", pages[1].Items[0].AccountID)
}
