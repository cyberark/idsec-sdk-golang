package common

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestTokenRefreshDoesNotRaceInFlightRequests asserts that refreshing the token
// while requests are in flight is safe.
//
// This is the defect the session was made copy-on-write to fix. A refresh wrote
// the token, the token type and the authorization header directly on the
// client, while other goroutines were reading the header map to build their
// own requests. A refresh is not a rare event: the client refreshes on a 401,
// which can arrive while any number of other requests are in flight through the
// same client.
//
// Run with -race.
func TestTokenRefreshDoesNotRaceInFlightRequests(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewIdsecClient(server.URL, "initial", "Bearer", "Authorization", nil, nil, "test-service", false)

	const iterations = 32
	var waitGroup sync.WaitGroup
	for index := range iterations {
		waitGroup.Add(2)
		go func(index int) {
			defer waitGroup.Done()
			response, err := client.Get(context.Background(), fmt.Sprintf("/route/%d", index), nil)
			if err != nil {
				t.Errorf("Request %d failed: %v", index, err)
				return
			}
			_ = response.Body.Close()
		}(index)
		go func(index int) {
			defer waitGroup.Done()
			client.UpdateToken(fmt.Sprintf("token-%d", index), "Bearer")
		}(index)
	}
	waitGroup.Wait()
}

// TestConcurrentHeaderChangesDoNotRaceRequests asserts that changing headers
// while requests are in flight is safe.
//
// Run with -race.
func TestConcurrentHeaderChangesDoNotRaceRequests(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewIdsecClient(server.URL, "", "", "Authorization", nil, nil, "test-service", false)

	const iterations = 32
	var waitGroup sync.WaitGroup
	for index := range iterations {
		waitGroup.Add(4)
		go func(index int) {
			defer waitGroup.Done()
			response, err := client.Get(context.Background(), fmt.Sprintf("/route/%d", index), nil)
			if err == nil {
				_ = response.Body.Close()
			}
		}(index)
		go func(index int) {
			defer waitGroup.Done()
			client.SetHeader(fmt.Sprintf("X-Custom-%d", index), "value")
		}(index)
		go func(index int) {
			defer waitGroup.Done()
			client.RemoveHeader(fmt.Sprintf("X-Custom-%d", index))
		}(index)
		go func() {
			defer waitGroup.Done()
			client.GetHeaders()
		}()
	}
	waitGroup.Wait()
}

// A request must send one consistent set of headers. Reading the session once
// per request is what stops a refresh landing between the body being encoded
// and the headers being written, which would send a new token's header on a
// request encoded for the old one.
func TestRequestSendsAConsistentTokenHeader(t *testing.T) {
	t.Parallel()

	var seenLock sync.Mutex
	seen := make(map[string]bool)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenLock.Lock()
		seen[r.Header.Get("Authorization")] = true
		seenLock.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewIdsecClient(server.URL, "initial", "Bearer", "Authorization", nil, nil, "test-service", false)

	response, err := client.Get(context.Background(), "/route", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	_ = response.Body.Close()

	client.UpdateToken("refreshed", "Bearer")
	response, err = client.Get(context.Background(), "/route", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	_ = response.Body.Close()

	seenLock.Lock()
	defer seenLock.Unlock()
	for _, expected := range []string{"Bearer initial", "Bearer refreshed"} {
		if !seen[expected] {
			t.Errorf("No request carried %q; saw %v", expected, seen)
		}
	}
}

// GetHeaders documents that it returns a copy, so mutating what it returns must
// not change what the client sends.
func TestGetHeadersReturnsACopy(t *testing.T) {
	t.Parallel()

	client := NewIdsecClient("https://example.com", "", "", "Authorization", nil, nil, "test-service", false)
	client.SetHeader("X-Original", "value")

	headers := client.GetHeaders()
	headers["X-Original"] = "tampered"
	headers["X-Added"] = "added"

	current := client.GetHeaders()
	if current["X-Original"] != "value" {
		t.Errorf("Client header was changed through the returned map: %q", current["X-Original"])
	}
	if _, added := current["X-Added"]; added {
		t.Error("A header added to the returned map reached the client")
	}
}

// A session is published whole, so a caller that has read one keeps seeing a
// consistent set of headers even as later changes are published.
func TestPublishedSessionIsNotChangedByLaterUpdates(t *testing.T) {
	t.Parallel()

	client := NewIdsecClient("https://example.com", "first", "Bearer", "Authorization", nil, nil, "test-service", false)

	held := client.currentSession()
	heldToken := held.token
	heldAuthorization := held.headers["Authorization"]

	client.UpdateToken("second", "Bearer")
	client.SetHeader("X-Late", "late")

	if held.token != heldToken {
		t.Errorf("Held session's token changed to %q", held.token)
	}
	if held.headers["Authorization"] != heldAuthorization {
		t.Errorf("Held session's authorization changed to %q", held.headers["Authorization"])
	}
	if _, late := held.headers["X-Late"]; late {
		t.Error("A header published later appeared in the held session")
	}

	current := client.currentSession()
	if !strings.HasSuffix(current.headers["Authorization"], "second") {
		t.Errorf("Current session did not pick up the new token: %q", current.headers["Authorization"])
	}
}
