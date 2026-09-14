package common

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// headerService stands in for an SDK service issuing requests through a client.
type headerService struct {
	client *IdsecClient
}

// FetchSafe names the operation the request should be reported under.
func (s *headerService) FetchSafe(ctx context.Context, route string) error {
	response, err := s.client.Get(ctx, route, nil)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

// telemetryField returns the value a decoded telemetry header reports for a
// metric short name.
func telemetryField(t *testing.T, header string, shortName string) string {
	t.Helper()

	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("Telemetry header was not base64: %v", err)
	}
	for _, pair := range strings.Split(string(decoded), "&") {
		name, value, found := strings.Cut(pair, "=")
		if found && name == shortName {
			return value
		}
	}
	return ""
}

// TestTelemetryHeaderDescribesTheRequestItIsSentOn walks the whole chain, from a
// service calling the client through to the header on the wire, and asserts
// that concurrent requests each report their own route and operation.
//
// This is the end the defect was visible from: while the route and operation
// were stored on the shared collector, requests overlapping in time could go
// out reporting each other's, and the collector's unsynchronised writes were a
// race in their own right.
//
// Run with -race.
func TestTelemetryHeaderDescribesTheRequestItIsSentOn(t *testing.T) {
	t.Parallel()

	var recordedLock sync.Mutex
	recorded := make(map[string]string)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordedLock.Lock()
		recorded[r.URL.Path] = r.Header.Get("X-Cybr-Telemetry")
		recordedLock.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewIdsecClient(server.URL, "", "", "", nil, nil, "test-service", false)
	service := &headerService{client: client}

	const requests = 32
	var waitGroup sync.WaitGroup
	for requestIndex := range requests {
		waitGroup.Add(1)
		go func(requestIndex int) {
			defer waitGroup.Done()
			route := fmt.Sprintf("/route/%d", requestIndex)
			if err := service.FetchSafe(context.Background(), route); err != nil {
				t.Errorf("Request %d failed: %v", requestIndex, err)
			}
		}(requestIndex)
	}
	waitGroup.Wait()

	recordedLock.Lock()
	defer recordedLock.Unlock()

	if len(recorded) != requests {
		t.Fatalf("Recorded %d requests, want %d", len(recorded), requests)
	}
	for requestIndex := range requests {
		route := fmt.Sprintf("/route/%d", requestIndex)
		header, ok := recorded[route]
		if !ok {
			t.Errorf("No request recorded for route %s", route)
			continue
		}
		if header == "" {
			t.Errorf("Route %s carried no telemetry header", route)
			continue
		}
		if reported := telemetryField(t, header, "mm.rt"); reported != route {
			t.Errorf("Route %s reported route %q", route, reported)
		}
		if reported := telemetryField(t, header, "mm.op"); reported != "FetchSafe" {
			t.Errorf("Route %s reported operation %q, want FetchSafe", route, reported)
		}
		if reported := telemetryField(t, header, "mm.cls"); reported != "headerService" {
			t.Errorf("Route %s reported class %q, want headerService", route, reported)
		}
		if reported := telemetryField(t, header, "mm.svc"); reported != "test-service" {
			t.Errorf("Route %s reported service %q, want test-service", route, reported)
		}
	}
}
