package pagination

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// testItem is the generic decode target used across ListPaginated tests.
type testItem struct {
	ID   string `json:"id" mapstructure:"id"`
	Name string `json:"name" mapstructure:"name"`
}

// defaultDecode mirrors the default extract + mapstructure decode path that used
// to live in the engine and now belongs to the caller-supplied Decode callback.
func defaultDecode(resultMap map[string]interface{}) ([]*testItem, error) {
	rawItems, err := ExtractItemsFromResult(resultMap, "items")
	if err != nil {
		return nil, err
	}
	var items []*testItem
	if err := mapstructure.Decode(rawItems, &items); err != nil {
		return nil, fmt.Errorf("failed to validate items: %w", err)
	}
	return items, nil
}

// eventLog records ordered events (e.g. "get:1", "close:p1") across goroutines
// so tests can assert relative ordering, such as a page's body being closed
// before the next page is requested.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.events))
	copy(out, l.events)
	return out
}

func indexOf(events []string, target string) int {
	for i, e := range events {
		if e == target {
			return i
		}
	}
	return -1
}

// trackingBody is an io.ReadCloser that records when Close is called, so tests
// can assert per-page close ordering and detect leaked/unclosed bodies.
type trackingBody struct {
	r      *strings.Reader
	label  string
	log    *eventLog
	closed bool
}

func newTrackingBody(payload, label string, log *eventLog) *trackingBody {
	return &trackingBody{r: strings.NewReader(payload), label: label, log: log}
}

func (b *trackingBody) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *trackingBody) Close() error {
	b.closed = true
	if b.log != nil {
		b.log.add("close:" + b.label)
	}
	return nil
}

func newResponse(status int, payload, label string, log *eventLog) (*http.Response, *trackingBody) {
	body := newTrackingBody(payload, label, log)
	return &http.Response{StatusCode: status, Body: body}, body
}

// queuedResp is a canned (response, error) pair returned by fakeFetcher.fetch in order.
type queuedResp struct {
	resp *http.Response
	err  error
}

// fakeFetcher is a test double whose fetch method satisfies the Fetch type. It
// returns a queued sequence of responses/errors and records each call. It can
// optionally block on a given call number until a release channel is closed, to
// deterministically interleave test actions (e.g. context cancellation) with the
// producer goroutine.
type fakeFetcher struct {
	mu        sync.Mutex
	queue     []queuedResp
	log       *eventLog
	callCount int
	blockOn   int
	release   chan struct{}
}

func (g *fakeFetcher) fetch(_ context.Context, query map[string]string) (*http.Response, map[string]string, error) {
	g.mu.Lock()
	g.callCount++
	callNum := g.callCount
	var next queuedResp
	if len(g.queue) > 0 {
		next = g.queue[0]
		g.queue = g.queue[1:]
	} else {
		next = queuedResp{err: fmt.Errorf("fakeFetcher: no more responses queued")}
	}
	g.mu.Unlock()

	if g.log != nil {
		g.log.add(fmt.Sprintf("get:%d", callNum))
	}

	if g.blockOn != 0 && g.blockOn == callNum && g.release != nil {
		<-g.release
	}

	return next.resp, query, next.err
}

// collectAll drains the page channel until it closes, guarding against a hang.
func collectAll(t *testing.T, pages <-chan *common.IdsecPage[testItem]) []*testItem {
	t.Helper()
	var items []*testItem
	timeout := time.After(3 * time.Second)
	for {
		select {
		case page, ok := <-pages:
			if !ok {
				return items
			}
			items = append(items, page.Items...)
		case <-timeout:
			t.Fatal("timed out collecting pages")
			return nil
		}
	}
}

// waitErr reads the (at most one) value from the error channel, guarding against a hang.
func waitErr(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for error channel")
		return nil
	}
}

func TestListPaginatedSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		build     func() (*fakeFetcher, ListPaginatedConfig[testItem])
		wantIDs   []string
		wantCalls int
	}{
		{
			name: "success_multi_page_walks_next_link",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp1, _ := newResponse(200, `{"value":[{"id":"1","name":"a"}],"next_link":"https://pvwa.example/next?offset=10"}`, "p1", nil)
				resp2, _ := newResponse(200, `{"value":[{"id":"2","name":"b"}]}`, "p2", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp1}, {resp: resp2}}}
				cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
				return getter, cfg
			},
			wantIDs:   []string{"1", "2"},
			wantCalls: 2,
		},
		{
			name: "success_single_page_no_next_link",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp1, _ := newResponse(200, `{"value":[{"id":"1","name":"a"}]}`, "p1", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp1}}}
				cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
				return getter, cfg
			},
			wantIDs:   []string{"1"},
			wantCalls: 1,
		},
		{
			name: "success_next_query_hook",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp1, _ := newResponse(200, `{"value":[{"id":"1","name":"a"}]}`, "p1", nil)
				resp2, _ := newResponse(200, `{"value":[{"id":"2","name":"b"}]}`, "p2", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp1}, {resp: resp2}}}
				calls := 0
				cfg := ListPaginatedConfig[testItem]{
					ResourceName: "items",
					Decode:       defaultDecode,
					NextQuery: func(_ map[string]interface{}, _ map[string]string) (map[string]string, bool) {
						calls++
						if calls == 1 {
							return map[string]string{"offset": "10"}, true
						}
						return nil, false
					},
				}
				return getter, cfg
			},
			wantIDs:   []string{"1", "2"},
			wantCalls: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			getter, cfg := tt.build()
			pages, errCh := ListPaginated(context.Background(), getter.fetch, cfg)
			items := collectAll(t, pages)
			if err := waitErr(t, errCh); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(items) != len(tt.wantIDs) {
				t.Fatalf("len(items) = %d, want %d", len(items), len(tt.wantIDs))
			}
			for i, want := range tt.wantIDs {
				if items[i].ID != want {
					t.Fatalf("items[%d].ID = %q, want %q", i, items[i].ID, want)
				}
			}
			if getter.callCount != tt.wantCalls {
				t.Fatalf("callCount = %d, want %d", getter.callCount, tt.wantCalls)
			}
		})
	}
}

func TestListPaginatedErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		build        func() (*fakeFetcher, ListPaginatedConfig[testItem])
		wantItemsLen int
		after        func(t *testing.T)
	}{
		{
			name: "error_transport_get_failure",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				getter := &fakeFetcher{queue: []queuedResp{{err: fmt.Errorf("transport boom")}}}
				cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
				return getter, cfg
			},
			wantItemsLen: 0,
		},
		{
			name: "error_http_non_200_terminal",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp, _ := newResponse(500, `{"error":"boom"}`, "err1", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
				cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
				return getter, cfg
			},
			wantItemsLen: 0,
		},
		{
			name: "error_decode_invalid_json",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp, _ := newResponse(200, `not-json{`, "bad", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
				cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
				return getter, cfg
			},
			wantItemsLen: 0,
		},
		{
			name: "error_unexpected_result_type",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp, _ := newResponse(200, `[1,2,3]`, "arr", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
				cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
				return getter, cfg
			},
			wantItemsLen: 0,
		},
		{
			name: "error_decode_extract",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp, _ := newResponse(200, `{"value":[]}`, "empty", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
				cfg := ListPaginatedConfig[testItem]{
					ResourceName: "items",
					Decode: func(map[string]interface{}) ([]*testItem, error) {
						return nil, fmt.Errorf("extract boom")
					},
				}
				return getter, cfg
			},
			wantItemsLen: 0,
		},
		{
			name: "error_entry_not_map",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp, _ := newResponse(200, `{"value":[1,2]}`, "scalar", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
				cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
				return getter, cfg
			},
			wantItemsLen: 0,
		},
		{
			name: "error_decode_returns_error",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp, _ := newResponse(200, `{"value":[{"id":"1","name":"a"}]}`, "ok1", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
				cfg := ListPaginatedConfig[testItem]{
					ResourceName: "items",
					Decode: func(map[string]interface{}) ([]*testItem, error) {
						return nil, fmt.Errorf("decode boom")
					},
				}
				return getter, cfg
			},
			wantItemsLen: 0,
		},
		{
			name: "error_decode_bad_shape",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp, _ := newResponse(200, `{"value":[{"id":{"nested":"x"},"name":"a"}]}`, "bad-shape", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
				cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
				return getter, cfg
			},
			wantItemsLen: 0,
		},
		{
			name: "error_next_query_parse",
			build: func() (*fakeFetcher, ListPaginatedConfig[testItem]) {
				resp, _ := newResponse(200, `{"value":[{"id":"1","name":"a"}],"next_link":"://not-a-valid-url"}`, "p1", nil)
				getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
				cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
				return getter, cfg
			},
			wantItemsLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			getter, cfg := tt.build()
			pages, errCh := ListPaginated(context.Background(), getter.fetch, cfg)
			items := collectAll(t, pages)
			err := waitErr(t, errCh)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if len(items) != tt.wantItemsLen {
				t.Fatalf("len(items) = %d, want %d", len(items), tt.wantItemsLen)
			}
			if tt.after != nil {
				tt.after(t)
			}
		})
	}
}

func TestListPaginatedNon200BodyClosed(t *testing.T) {
	t.Parallel()
	t.Run("error_http_non_200_terminal_closes_body", func(t *testing.T) {
		t.Parallel()
		resp, body := newResponse(500, `{"error":"boom"}`, "err1", nil)
		getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
		cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}

		pages, errCh := ListPaginated(context.Background(), getter.fetch, cfg)
		items := collectAll(t, pages)
		if len(items) != 0 {
			t.Fatalf("len(items) = %d, want 0", len(items))
		}
		if err := waitErr(t, errCh); err == nil {
			t.Fatal("expected error, got nil")
		}
		if !body.closed {
			t.Fatal("expected non-200 response body to be closed")
		}
	})
}

func TestListPaginatedCustomDecode(t *testing.T) {
	t.Parallel()
	t.Run("success_decode_normalizes_and_enriches", func(t *testing.T) {
		t.Parallel()

		resp1, _ := newResponse(200, `{"value":[{"id":"1","name":"a"}],"next_link":"https://pvwa.example/next?offset=10"}`, "p1", nil)
		resp2, _ := newResponse(200, `{"value":[{"id":"2","name":"b"},{"id":"3","name":"c"}]}`, "p2", nil)
		getter := &fakeFetcher{queue: []queuedResp{{resp: resp1}, {resp: resp2}}}

		var mu sync.Mutex
		var decodedSizes []int

		// Decode now owns extract + normalize + decode + enrich for the page.
		cfg := ListPaginatedConfig[testItem]{
			ResourceName: "items",
			Decode: func(resultMap map[string]interface{}) ([]*testItem, error) {
				rawItems, err := ExtractItemsFromResult(resultMap, "items")
				if err != nil {
					return nil, err
				}
				for _, raw := range rawItems {
					itemMap, ok := raw.(map[string]interface{})
					if !ok {
						return nil, fmt.Errorf("failed to list items: unexpected entry type %T", raw)
					}
					if name, ok := itemMap["name"].(string); ok {
						itemMap["name"] = "normalized-" + name
					}
				}
				var items []*testItem
				if err := mapstructure.Decode(rawItems, &items); err != nil {
					return nil, fmt.Errorf("failed to validate items: %w", err)
				}
				mu.Lock()
				decodedSizes = append(decodedSizes, len(items))
				mu.Unlock()
				return items, nil
			},
		}

		pages, errCh := ListPaginated(context.Background(), getter.fetch, cfg)
		items := collectAll(t, pages)
		if err := waitErr(t, errCh); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 3 {
			t.Fatalf("len(items) = %d, want 3", len(items))
		}
		for _, item := range items {
			if !strings.HasPrefix(item.Name, "normalized-") {
				t.Fatalf("item.Name = %q, want normalized- prefix", item.Name)
			}
		}

		mu.Lock()
		defer mu.Unlock()
		if len(decodedSizes) != 2 {
			t.Fatalf("Decode called %d times, want 2", len(decodedSizes))
		}
		if decodedSizes[0] != 1 || decodedSizes[1] != 2 {
			t.Fatalf("decodedSizes = %v, want [1 2]", decodedSizes)
		}
	})
}

func TestListPaginatedBodyClosedPerPage(t *testing.T) {
	t.Parallel()
	t.Run("assert_body_closed_per_page", func(t *testing.T) {
		t.Parallel()

		log := &eventLog{}
		resp1, body1 := newResponse(200, `{"value":[{"id":"1","name":"a"}],"next_link":"https://pvwa.example/next?offset=10"}`, "p1", log)
		resp2, body2 := newResponse(200, `{"value":[{"id":"2","name":"b"}]}`, "p2", log)
		getter := &fakeFetcher{queue: []queuedResp{{resp: resp1}, {resp: resp2}}, log: log}
		cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}

		pages, errCh := ListPaginated(context.Background(), getter.fetch, cfg)
		items := collectAll(t, pages)
		if err := waitErr(t, errCh); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("len(items) = %d, want 2", len(items))
		}
		if !body1.closed || !body2.closed {
			t.Fatal("expected both page bodies to be closed")
		}

		events := log.snapshot()
		closeP1 := indexOf(events, "close:p1")
		getCall2 := indexOf(events, "get:2")
		if closeP1 == -1 || getCall2 == -1 {
			t.Fatalf("missing expected events in log: %v", events)
		}
		if closeP1 > getCall2 {
			t.Fatalf("expected close:p1 (index %d) before get:2 (index %d): %v", closeP1, getCall2, events)
		}
	})
}

func TestListPaginatedContextCancellation(t *testing.T) {
	t.Parallel()
	t.Run("context_cancellation", func(t *testing.T) {
		t.Parallel()

		resp1, _ := newResponse(200, `{"value":[{"id":"1","name":"a"}],"next_link":"https://pvwa.example/next?offset=10"}`, "p1", nil)
		resp2, _ := newResponse(200, `{"value":[{"id":"2","name":"b"}]}`, "p2", nil)
		release := make(chan struct{})
		getter := &fakeFetcher{
			queue:   []queuedResp{{resp: resp1}, {resp: resp2}},
			blockOn: 2,
			release: release,
		}

		cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}
		ctx, cancel := context.WithCancel(context.Background())
		pages, errCh := ListPaginated(ctx, getter.fetch, cfg)

		select {
		case page, ok := <-pages:
			if !ok {
				t.Fatal("expected first page, got closed channel")
			}
			if len(page.Items) != 1 {
				t.Fatalf("len(items) = %d, want 1", len(page.Items))
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for first page")
		}

		// Cancel while the producer is fetching the next page, then release it so
		// it reaches the guarded page-channel send with no active receiver.
		cancel()
		close(release)

		select {
		case err := <-errCh:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for error channel")
		}

		select {
		case _, ok := <-pages:
			if ok {
				t.Fatal("expected page channel closed after cancellation")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for page channel to close")
		}
	})
}

// TestListPaginatedSeedsNextQueryFromFetcher verifies the engine passes nil on the first
// call (so the fetcher supplies its own starting query) and then feeds NextQuery the query
// the fetcher reported, without the caller passing an initial query.
func TestListPaginatedSeedsNextQueryFromFetcher(t *testing.T) {
	t.Parallel()
	t.Run("success_next_query_seeded_from_fetcher", func(t *testing.T) {
		t.Parallel()

		resp1, _ := newResponse(200, `{"value":[{"id":"1","name":"a"}]}`, "p1", nil)
		resp2, _ := newResponse(200, `{"value":[{"id":"2","name":"b"}]}`, "p2", nil)
		responses := []*http.Response{resp1, resp2}

		var mu sync.Mutex
		var fetchQueries []map[string]string
		var nextQueryCurrents []map[string]string

		fetch := func(_ context.Context, query map[string]string) (*http.Response, map[string]string, error) {
			if query == nil {
				query = map[string]string{"offset": "0"}
			}
			mu.Lock()
			idx := len(fetchQueries)
			fetchQueries = append(fetchQueries, query)
			mu.Unlock()
			return responses[idx], query, nil
		}

		cfg := ListPaginatedConfig[testItem]{
			ResourceName: "items",
			Decode:       defaultDecode,
			NextQuery: func(_ map[string]interface{}, current map[string]string) (map[string]string, bool) {
				mu.Lock()
				nextQueryCurrents = append(nextQueryCurrents, current)
				n := len(nextQueryCurrents)
				mu.Unlock()
				if n == 1 {
					return map[string]string{"offset": "1"}, true
				}
				return nil, false
			},
		}

		pages, errCh := ListPaginated(context.Background(), fetch, cfg)
		items := collectAll(t, pages)
		if err := waitErr(t, errCh); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(items) != 2 {
			t.Fatalf("len(items) = %d, want 2", len(items))
		}

		mu.Lock()
		defer mu.Unlock()
		if len(nextQueryCurrents) != 2 {
			t.Fatalf("NextQuery called %d times, want 2", len(nextQueryCurrents))
		}
		if nextQueryCurrents[0]["offset"] != "0" {
			t.Fatalf("first NextQuery current = %v, want offset=0 (from fetcher's nil-seeded query)", nextQueryCurrents[0])
		}
		if len(fetchQueries) != 2 || fetchQueries[1]["offset"] != "1" {
			t.Fatalf("fetch queries = %v, want second call offset=1 (engine-advanced)", fetchQueries)
		}
	})
}

func TestListAllPaginated(t *testing.T) {
	t.Parallel()

	t.Run("success_collects_all_pages_into_single_page", func(t *testing.T) {
		t.Parallel()

		resp1, _ := newResponse(200, `{"value":[{"id":"1","name":"a"}],"next_link":"https://pvwa.example/next?offset=10"}`, "p1", nil)
		resp2, _ := newResponse(200, `{"value":[{"id":"2","name":"b"}]}`, "p2", nil)
		getter := &fakeFetcher{queue: []queuedResp{{resp: resp1}, {resp: resp2}}}
		cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}

		pages, err := ListAllPaginated(context.Background(), getter.fetch, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		items := collectAll(t, pages)
		if len(items) != 2 {
			t.Fatalf("len(items) = %d, want 2 (all pages collected into one)", len(items))
		}
		if items[0].ID != "1" || items[1].ID != "2" {
			t.Fatalf("items = %+v, want ids [1 2]", items)
		}
		if getter.callCount != 2 {
			t.Fatalf("callCount = %d, want 2", getter.callCount)
		}
	})

	t.Run("error_returns_nil_channel_and_error", func(t *testing.T) {
		t.Parallel()

		resp, _ := newResponse(500, `{"error":"boom"}`, "err1", nil)
		getter := &fakeFetcher{queue: []queuedResp{{resp: resp}}}
		cfg := ListPaginatedConfig[testItem]{ResourceName: "items", Decode: defaultDecode}

		pages, err := ListAllPaginated(context.Background(), getter.fetch, cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if pages != nil {
			t.Fatalf("expected nil page channel on error, got %v", pages)
		}
	})
}
