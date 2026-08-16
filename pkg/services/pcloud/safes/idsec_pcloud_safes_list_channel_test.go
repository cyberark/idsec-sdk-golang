package safes_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pcloudint "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/internal"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
)

// List error-propagation and pagination regression tests (minimal set):
//   - mid-pagination HTTP error after a good first page -> returned error, no channel;
//   - first request fails -> returned error, no channel;
//   - two OK pages -> single combined page with items from both requests, no error.
//
// ListMembers: one mid-pagination case for the distinct /members route and member decode path.
func newTestPCloudSafesService(parts *pcloudint.MockISPServiceParts) *safes.IdsecPCloudSafesService {
	return &safes.IdsecPCloudSafesService{
		IdsecBaseService:    parts.BaseService,
		IdsecISPBaseService: parts.ISPBase,
	}
}

func TestSafesList_midPaginationHTTPError_returnsErr(t *testing.T) {
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

	ch, err := newTestPCloudSafesService(parts).ListBy(&safesmodels.IdsecPCloudSafesFilters{})
	require.Error(t, err)
	require.Nil(t, ch) // partial results from page 1 must NOT leak through
	require.GreaterOrEqual(t, listGETs, 2,
		"pagination must issue a second GET when the API returns nextLink (decoded map key is next_link)")
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

	ch, err := newTestPCloudSafesService(parts).ListBy(&safesmodels.IdsecPCloudSafesFilters{})
	require.Error(t, err)
	require.Nil(t, ch)
	require.Equal(t, 1, listGETs)
}

func TestSafesList_happyMultiPageCombinedIntoSinglePage(t *testing.T) {
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

	ch, err := newTestPCloudSafesService(parts).ListBy(&safesmodels.IdsecPCloudSafesFilters{})
	require.NoError(t, err)
	require.Equal(t, 2, listGETs)

	var pages []*safes.IdsecPCloudSafesPage
	for p := range ch {
		pages = append(pages, p)
	}
	require.Len(t, pages, 1, "ListAllPaginated collapses all pages into a single page")
	require.Len(t, pages[0].Items, 2)
	require.Equal(t, "sid-1", pages[0].Items[0].SafeID)
	require.Equal(t, "sid-2", pages[0].Items[1].SafeID)
}

// TestSafesListContext_cancelStopsPagination verifies that cancelling ctx while pagination is
// in flight against an endpoint that advertises another page forever unblocks the call (via the
// underlying HTTP request failing with context.Canceled) instead of hanging indefinitely.
func TestSafesListContext_cancelStopsPagination(t *testing.T) {
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
	done := make(chan error, 1)
	go func() {
		_, err := newTestPCloudSafesService(parts).ListByContext(ctx, &safesmodels.IdsecPCloudSafesFilters{})
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

// TestSafesListMembersContext_cancelStopsPagination mirrors the safes-list cancellation test for
// the distinct safe-members producer (which enriches members before returning).
func TestSafesListMembersContext_cancelStopsPagination(t *testing.T) {
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
	done := make(chan error, 1)
	go func() {
		_, err := newTestPCloudSafesService(parts).ListMembersByContext(ctx, &safesmodels.IdsecPCloudSafeMembersFilters{SafeID: safeID})
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.Error(t, err, "cancelled pagination must surface an error instead of an empty success")
	case <-time.After(3 * time.Second):
		t.Fatal("ListMembersByContext did not return after context cancellation (possible hang)")
	}
}

func TestSafesListMembers_midPaginationHTTPError_returnsErr(t *testing.T) {
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
	require.Error(t, err)
	require.Nil(t, ch)
	require.GreaterOrEqual(t, listGETs, 2)
}

// TestSafesListBy_appliesAllQueryParams verifies that a fully populated filter maps each field to
// the correct outgoing query-param key/value (guards against a mis-keyed param going unnoticed).
func TestSafesListBy_appliesAllQueryParams(t *testing.T) {
	t.Parallel()
	var gotQuery url.Values
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/safes" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"value":[{"safe_url_id":"sid-1","safe_name":"S1"}]}`)
	})
	parts, cleanup := pcloudint.SetupMockISPServiceParts(t, h)
	t.Cleanup(cleanup)

	ch, err := newTestPCloudSafesService(parts).ListBy(&safesmodels.IdsecPCloudSafesFilters{
		Search: "prod",
		Sort:   "safeName desc",
		Offset: 10,
		Limit:  25,
	})
	require.NoError(t, err)
	require.NotNil(t, ch)
	for range ch {
	}

	require.Equal(t, "prod", gotQuery.Get("search"))
	require.Equal(t, "safeName desc", gotQuery.Get("sort"))
	require.Equal(t, "10", gotQuery.Get("offset"))
	require.Equal(t, "25", gotQuery.Get("limit"))
}
