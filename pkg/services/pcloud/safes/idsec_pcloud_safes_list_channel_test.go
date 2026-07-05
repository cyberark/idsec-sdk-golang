package safes_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
)

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

// List channel regression tests (minimal set):
//   - mid-pagination HTTP error after a good first page → terminal page with Err (not silent close);
//   - first request fails → single terminal Err page (not confused with empty list);
//   - two OK pages → no Err on any page (next_link success path).
//
// ListMembers: one mid-pagination case for the distinct /members route and member decode path.
func newTestPCloudSafesService(parts *pcloudint.MockISPServiceParts) *safes.IdsecPCloudSafesService {
	return &safes.IdsecPCloudSafesService{
		IdsecBaseService:    parts.BaseService,
		IdsecISPBaseService: parts.ISPBase,
	}
}

func drainSafesListPages(t *testing.T, svc *safes.IdsecPCloudSafesService) []*safes.IdsecPCloudSafesPage {
	t.Helper()
	ch, err := svc.ListBy(&safesmodels.IdsecPCloudSafesFilters{})
	require.NoError(t, err)
	var pages []*safes.IdsecPCloudSafesPage
	for p := range ch {
		pages = append(pages, p)
	}
	return pages
}

func requireSafesListPropagatesPage2Failure(t *testing.T, listGETs int, pages []*safes.IdsecPCloudSafesPage) {
	t.Helper()
	require.GreaterOrEqual(t, listGETs, 2,
		"pagination must issue a second GET when the API returns nextLink (decoded map key is next_link)")
	require.GreaterOrEqual(t, len(pages), 2, "expect at least one data page and a terminal error page")
	require.NoError(t, pages[0].Err, "data pages must not set Err")
	require.Error(t, pages[len(pages)-1].Err, "last page must carry Err after a page-2+ failure")
}

func TestSafesList_midPaginationHTTPError_emitsTerminalErrPage(t *testing.T) {
	t.Parallel()
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/safes" {
			http.NotFound(w, r)
			return
		}
		listGETs++
		n := listGETs
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			next := "http://" + r.Host + "/api/safes?page=2"
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"value":[{"safe_url_id":"sid-1","safe_name":"S1"}],"nextLink":%q}`, next)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"second page failed"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	pages := drainSafesListPages(t, newTestPCloudSafesService(parts))
	requireSafesListPropagatesPage2Failure(t, listGETs, pages)
}

func TestSafesList_channelPropagatesFirstPageFailure(t *testing.T) {
	t.Parallel()
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/safes" {
			http.NotFound(w, r)
			return
		}
		listGETs++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"auth"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	pages := drainSafesListPages(t, newTestPCloudSafesService(parts))
	require.Equal(t, 1, listGETs)
	require.Len(t, pages, 1)
	require.Error(t, pages[0].Err)
}

func TestSafesList_happyMultiPageNoTerminalErr(t *testing.T) {
	t.Parallel()
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/safes" {
			http.NotFound(w, r)
			return
		}
		listGETs++
		n := listGETs
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			next := "http://" + r.Host + "/api/safes?page=2"
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"value":[{"safe_url_id":"sid-1","safe_name":"S1"}],"nextLink":%q}`, next)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"value":[{"safe_url_id":"sid-2","safe_name":"S2"}]}`)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	pages := drainSafesListPages(t, newTestPCloudSafesService(parts))
	require.Equal(t, 2, listGETs)
	require.Len(t, pages, 2)
	for i, p := range pages {
		require.NoError(t, p.Err, "page %d", i)
	}
	require.Len(t, pages[0].Items, 1)
	require.Len(t, pages[1].Items, 1)
	require.Equal(t, "sid-1", pages[0].Items[0].SafeID)
	require.Equal(t, "sid-2", pages[1].Items[0].SafeID)
}

// TestSafesListContext_cancelReleasesProducer verifies the goroutine-leak fix for the safes
// list producer: cancelling the context after abandoning iteration releases the goroutine.
func TestSafesListContext_cancelReleasesProducer(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/safes" {
			http.NotFound(w, r)
			return
		}
		next := "http://" + r.Host + "/api/safes?page=next"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"value":[{"safe_url_id":"sid-1","safe_name":"S1"}],"nextLink":%q}`, next)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := newTestPCloudSafesService(parts).ListByContext(ctx, &safesmodels.IdsecPCloudSafesFilters{})
	require.NoError(t, err)

	first, ok := <-ch
	require.True(t, ok, "expected at least one page before abandoning iteration")
	require.NoError(t, first.Err)

	cancel()
	requireProducerExits(t, ch)
}

// TestSafesListMembersContext_cancelReleasesProducer verifies the goroutine-leak fix for the
// distinct safe-members producer (which enriches members before sending).
func TestSafesListMembersContext_cancelReleasesProducer(t *testing.T) {
	t.Parallel()
	const safeID = "safe1"
	wantPath := "/api/safes/" + safeID + "/members"
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		next := "http://" + r.Host + wantPath + "?page=next"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"value":[{"safe_url_id":"sid","safe_name":"S","member_name":"m1","member_type":"User","permissions":{}}],"nextLink":%q}`, next)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := newTestPCloudSafesService(parts).ListMembersByContext(ctx, &safesmodels.IdsecPCloudSafeMembersFilters{SafeID: safeID})
	require.NoError(t, err)

	first, ok := <-ch
	require.True(t, ok, "expected at least one page before abandoning iteration")
	require.NoError(t, first.Err)

	cancel()
	requireProducerExits(t, ch)
}

func TestSafesListMembers_midPaginationHTTPError_emitsTerminalErrPage(t *testing.T) {
	t.Parallel()
	const safeID = "safe1"
	wantPath := "/api/safes/" + safeID + "/members"
	var listGETs int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		listGETs++
		n := listGETs
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			next := "http://" + r.Host + wantPath + "?page=2"
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"value":[{"safe_url_id":"sid","safe_name":"S","member_name":"m1","member_type":"User","permissions":{}}],"nextLink":%q}`, next)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"second page failed"}`))
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	svc := newTestPCloudSafesService(parts)
	ch, err := svc.ListMembers(&safesmodels.IdsecPCloudListSafeMembers{SafeID: safeID})
	require.NoError(t, err)
	var pages []*safes.IdsecPCloudSafeMembersPage
	for p := range ch {
		pages = append(pages, p)
	}
	require.GreaterOrEqual(t, listGETs, 2)
	require.GreaterOrEqual(t, len(pages), 2)
	require.NoError(t, pages[0].Err)
	require.Error(t, pages[len(pages)-1].Err)
}
