package common

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// eofHandler returns an http.HandlerFunc that hijacks and immediately closes
// the underlying TCP connection for the first failCount requests (producing a
// bare EOF on the client, exactly like a stale keep-alive connection being
// reused), then responds 200 OK for every subsequent request. The provided
// counter is incremented once per received request so tests can assert how many
// wire attempts were actually made.
func eofHandler(counter *int32, failCount int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(counter, 1)
		if n <= failCount {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			_ = conn.(net.Conn).Close()
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
}

// rateLimitHandler returns an http.HandlerFunc that responds 429 with the given
// Retry-After header for the first failCount requests, then 200 OK afterwards.
func rateLimitHandler(counter *int32, failCount int32, retryAfter string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(counter, 1)
		if n <= failCount {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
}

// newTestClient builds an IdsecClient pointed at the given plain-HTTP test
// server. It bypasses the https:// prefixing done by the constructor by setting
// BaseURL directly, and applies fast, deterministic transient-retry backoff so
// the tests run quickly.
func newTestClient(serverURL string, retryCount int) *IdsecClient {
	client := NewSimpleIdsecClient("placeholder")
	client.BaseURL = serverURL
	client.SetTransientRetry(retryCount, time.Millisecond, 5*time.Millisecond)
	return client
}

// TestTransientRetry_EOF exercises the reproduction-and-fix for the production
// "Post ...: EOF" failures: a real connection close is turned into a recoverable
// error only when transient retry is enabled.
func TestTransientRetry_EOF(t *testing.T) {
	tests := []struct {
		name           string
		failCount      int32
		retryCount     int
		expectError    bool
		expectStatus   int
		expectAttempts int32
	}{
		{
			name:           "recovers_after_transient_eof_when_retry_enabled",
			failCount:      2,
			retryCount:     3,
			expectError:    false,
			expectStatus:   http.StatusOK,
			expectAttempts: 3, // 2 EOFs + 1 success
		},
		{
			name:           "single_eof_recovers_on_first_retry",
			failCount:      1,
			retryCount:     3,
			expectError:    false,
			expectStatus:   http.StatusOK,
			expectAttempts: 2, // 1 EOF + 1 success
		},
		{
			name:           "fails_on_eof_when_retry_disabled",
			failCount:      1,
			retryCount:     0,
			expectError:    true,
			expectAttempts: 1, // no retry, single failing attempt
		},
		{
			name:           "fails_after_exhausting_retries",
			failCount:      10,
			retryCount:     3,
			expectError:    true,
			expectAttempts: 4, // initial attempt + 3 retries
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var counter int32
			server := httptest.NewServer(eofHandler(&counter, tt.failCount))
			defer server.Close()

			client := newTestClient(server.URL, tt.retryCount)

			resp, err := client.Post(context.Background(), "query", map[string]string{"q": "value"})
			if resp != nil {
				_ = resp.Body.Close()
			}

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected an error, got nil (status recovered unexpectedly)")
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if resp == nil || resp.StatusCode != tt.expectStatus {
					t.Fatalf("expected status %d, got %v", tt.expectStatus, resp)
				}
			}

			if got := atomic.LoadInt32(&counter); got != tt.expectAttempts {
				t.Fatalf("expected %d wire attempts, got %d", tt.expectAttempts, got)
			}
		})
	}
}

// TestTransientRetry_RateLimit verifies that HTTP 429 responses are retried
// (honoring Retry-After) when transient retry is enabled, and surfaced to the
// caller unchanged when it is disabled.
func TestTransientRetry_RateLimit(t *testing.T) {
	tests := []struct {
		name           string
		failCount      int32
		retryCount     int
		retryAfter     string
		expectStatus   int
		expectAttempts int32
	}{
		{
			name:           "recovers_after_429_when_retry_enabled",
			failCount:      2,
			retryCount:     3,
			retryAfter:     "0",
			expectStatus:   http.StatusOK,
			expectAttempts: 3,
		},
		{
			name:           "recovers_after_429_without_retry_after_header",
			failCount:      1,
			retryCount:     3,
			retryAfter:     "",
			expectStatus:   http.StatusOK,
			expectAttempts: 2,
		},
		{
			name:           "returns_429_when_retry_disabled",
			failCount:      1,
			retryCount:     0,
			retryAfter:     "0",
			expectStatus:   http.StatusTooManyRequests,
			expectAttempts: 1,
		},
		{
			name:           "returns_429_after_exhausting_retries",
			failCount:      10,
			retryCount:     2,
			retryAfter:     "0",
			expectStatus:   http.StatusTooManyRequests,
			expectAttempts: 3,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var counter int32
			server := httptest.NewServer(rateLimitHandler(&counter, tt.failCount, tt.retryAfter))
			defer server.Close()

			client := newTestClient(server.URL, tt.retryCount)

			resp, err := client.Post(context.Background(), "query", map[string]string{"q": "value"})
			if err != nil {
				t.Fatalf("expected no transport error, got %v", err)
			}
			if resp == nil {
				t.Fatalf("expected a response, got nil")
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.expectStatus {
				t.Fatalf("expected status %d, got %d", tt.expectStatus, resp.StatusCode)
			}
			if got := atomic.LoadInt32(&counter); got != tt.expectAttempts {
				t.Fatalf("expected %d wire attempts, got %d", tt.expectAttempts, got)
			}
		})
	}
}

// TestTransientRetry_ContextCancellation ensures that a cancelled context stops
// retrying promptly instead of looping through the full backoff schedule.
func TestTransientRetry_ContextCancellation(t *testing.T) {
	t.Parallel()

	var counter int32
	// Always fail with EOF so the client would otherwise retry indefinitely.
	server := httptest.NewServer(eofHandler(&counter, 1<<30))
	defer server.Close()

	client := NewSimpleIdsecClient("placeholder")
	client.BaseURL = server.URL
	// Large backoff so cancellation, not exhaustion, is what stops the loop.
	client.SetTransientRetry(5, 10*time.Second, 30*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel up front

	start := time.Now()
	resp, err := client.Post(ctx, "query", map[string]string{"q": "value"})
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatalf("expected an error from cancelled context, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("expected prompt return on cancellation, took %s", elapsed)
	}
}
