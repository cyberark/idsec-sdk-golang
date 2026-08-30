package common

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

func mockResponse(statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString("")),
		Header:     make(http.Header),
	}
}

type fakeResource struct{ ID string }

// TestCreateWithGatewayTimeoutRecovery_NonGatewayTimeout verifies that a non-504 response is
// returned immediately without polling.
func TestCreateWithGatewayTimeoutRecovery_NonGatewayTimeout(t *testing.T) {
	calls := 0
	create := func() (*http.Response, error) {
		calls++
		return mockResponse(http.StatusCreated), nil
	}
	find := func() (*fakeResource, error) {
		t.Fatal("find should not be called on a non-504 response")
		return nil, nil
	}

	resp, found, err := CreateWithGatewayTimeoutRecovery(create, find)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Fatalf("expected found == nil, got %v", found)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
	if calls != 1 {
		t.Fatalf("expected 1 create call, got %d", calls)
	}
}

// TestCreateWithGatewayTimeoutRecovery_TransportError verifies that a transport-level error is
// surfaced immediately.
func TestCreateWithGatewayTimeoutRecovery_TransportError(t *testing.T) {
	sentinel := errors.New("connection refused")
	create := func() (*http.Response, error) { return nil, sentinel }
	find := func() (*fakeResource, error) { return nil, nil }

	resp, found, err := CreateWithGatewayTimeoutRecovery(create, find)
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if resp != nil || found != nil {
		t.Fatalf("expected nil response and found on error")
	}
}

// TestCreateWithGatewayTimeoutRecovery_504ThenFoundByPoll verifies that when the first POST
// returns 504 the helper polls find and returns the resource without retrying the POST.
func TestCreateWithGatewayTimeoutRecovery_504ThenFoundByPoll(t *testing.T) {
	createCalls := 0
	create := func() (*http.Response, error) {
		createCalls++
		return mockResponse(http.StatusGatewayTimeout), nil
	}
	resource := &fakeResource{ID: "abc"}
	findCalls := 0
	find := func() (*fakeResource, error) {
		findCalls++
		return resource, nil
	}

	resp, found, err := CreateWithGatewayTimeoutRecovery(create, find)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != resource {
		t.Fatalf("expected resource to be returned, got %v", found)
	}
	if resp != nil {
		t.Fatalf("expected nil response when resource is found by poll")
	}
	if createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", createCalls)
	}
	if findCalls == 0 {
		t.Fatalf("expected at least one find call")
	}
}

// TestCreateWithGatewayTimeoutRecovery_504PollNotFoundThenRetrySucceeds verifies the case where
// find finds nothing, the creation is retried, and the retry succeeds.
func TestCreateWithGatewayTimeoutRecovery_504PollNotFoundThenRetrySucceeds(t *testing.T) {
	origWindow, origInterval := CreateGatewayTimeoutFindWindow, CreateGatewayTimeoutFindInterval
	CreateGatewayTimeoutFindWindow = 50 * time.Millisecond
	CreateGatewayTimeoutFindInterval = 10 * time.Millisecond
	defer func() {
		CreateGatewayTimeoutFindWindow = origWindow
		CreateGatewayTimeoutFindInterval = origInterval
	}()

	createCalls := 0
	create := func() (*http.Response, error) {
		createCalls++
		if createCalls == 1 {
			return mockResponse(http.StatusGatewayTimeout), nil
		}
		return mockResponse(http.StatusCreated), nil
	}
	find := func() (*fakeResource, error) { return nil, nil }

	resp, found, err := CreateWithGatewayTimeoutRecovery(create, find)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Fatalf("expected found == nil, got %v", found)
	}
	if resp == nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 response on retry")
	}
	if createCalls != 2 {
		t.Fatalf("expected 2 create calls, got %d", createCalls)
	}
}

// TestCreateWithGatewayTimeoutRecovery_ExhaustedRetries verifies that after
// CreateGatewayTimeoutMaxRetries+1 consecutive 504s the final response is returned unchanged.
func TestCreateWithGatewayTimeoutRecovery_ExhaustedRetries(t *testing.T) {
	origWindow, origInterval := CreateGatewayTimeoutFindWindow, CreateGatewayTimeoutFindInterval
	CreateGatewayTimeoutFindWindow = 50 * time.Millisecond
	CreateGatewayTimeoutFindInterval = 10 * time.Millisecond
	defer func() {
		CreateGatewayTimeoutFindWindow = origWindow
		CreateGatewayTimeoutFindInterval = origInterval
	}()

	createCalls := 0
	create := func() (*http.Response, error) {
		createCalls++
		return mockResponse(http.StatusGatewayTimeout), nil
	}
	find := func() (*fakeResource, error) { return nil, nil }

	resp, found, err := CreateWithGatewayTimeoutRecovery(create, find)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Fatalf("expected found == nil after exhaustion")
	}
	if resp == nil || resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected the final 504 response to be returned")
	}
	expectedCalls := CreateGatewayTimeoutMaxRetries + 1
	if createCalls != expectedCalls {
		t.Fatalf("expected %d create calls, got %d", expectedCalls, createCalls)
	}
}

// TestCreateWithGatewayTimeoutRecovery_409WithoutGatewayTimeout_PassThrough verifies that a 409
// on the very first attempt (no prior 504) is returned as-is for the caller to handle.
func TestCreateWithGatewayTimeoutRecovery_409WithoutGatewayTimeout_PassThrough(t *testing.T) {
	calls := 0
	create := func() (*http.Response, error) {
		calls++
		return mockResponse(http.StatusConflict), nil
	}
	find := func() (*fakeResource, error) {
		t.Fatal("find should not be called on a first-attempt 409")
		return nil, nil
	}

	resp, found, err := CreateWithGatewayTimeoutRecovery(create, find)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Fatalf("expected found == nil, got %v", found)
	}
	if resp == nil || resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 response to be passed through")
	}
	if calls != 1 {
		t.Fatalf("expected 1 create call, got %d", calls)
	}
}

// TestCreateWithGatewayTimeoutRecovery_409AfterGatewayTimeout_Found verifies that a 409 on a
// retry after a prior 504 triggers a find, and the located resource is returned.
// find returns nil during the 504 poll (so the POST is retried) but the resource on the 409 poll.
func TestCreateWithGatewayTimeoutRecovery_409AfterGatewayTimeout_Found(t *testing.T) {
	origWindow, origInterval := CreateGatewayTimeoutFindWindow, CreateGatewayTimeoutFindInterval
	CreateGatewayTimeoutFindWindow = 50 * time.Millisecond
	CreateGatewayTimeoutFindInterval = 10 * time.Millisecond
	defer func() {
		CreateGatewayTimeoutFindWindow = origWindow
		CreateGatewayTimeoutFindInterval = origInterval
	}()

	createCalls := 0
	create := func() (*http.Response, error) {
		createCalls++
		if createCalls == 1 {
			return mockResponse(http.StatusGatewayTimeout), nil
		}
		return mockResponse(http.StatusConflict), nil
	}
	resource := &fakeResource{ID: "xyz"}
	// Return nil while the first (504) POST is still the last attempt; only return the
	// resource after the second POST (409) has been issued, keying on createCalls.
	find := func() (*fakeResource, error) {
		if createCalls < 2 {
			return nil, nil
		}
		return resource, nil
	}

	resp, found, err := CreateWithGatewayTimeoutRecovery(create, find)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != resource {
		t.Fatalf("expected resource to be returned, got %v", found)
	}
	if resp != nil {
		t.Fatalf("expected nil response when resource is found")
	}
	if createCalls != 2 {
		t.Fatalf("expected 2 create calls (1 504 + 1 409), got %d", createCalls)
	}
}

// TestCreateWithGatewayTimeoutRecovery_409AfterGatewayTimeout_NotFound verifies that a 409 after
// a prior 504 where find still cannot locate the resource results in an error.
func TestCreateWithGatewayTimeoutRecovery_409AfterGatewayTimeout_NotFound(t *testing.T) {
	origWindow, origInterval := CreateGatewayTimeoutFindWindow, CreateGatewayTimeoutFindInterval
	CreateGatewayTimeoutFindWindow = 50 * time.Millisecond
	CreateGatewayTimeoutFindInterval = 10 * time.Millisecond
	defer func() {
		CreateGatewayTimeoutFindWindow = origWindow
		CreateGatewayTimeoutFindInterval = origInterval
	}()

	createCalls := 0
	create := func() (*http.Response, error) {
		createCalls++
		if createCalls == 1 {
			return mockResponse(http.StatusGatewayTimeout), nil
		}
		return mockResponse(http.StatusConflict), nil
	}
	find := func() (*fakeResource, error) { return nil, nil }

	resp, found, err := CreateWithGatewayTimeoutRecovery(create, find)
	if err == nil {
		t.Fatalf("expected error when resource cannot be found after 409-after-504")
	}
	if resp != nil || found != nil {
		t.Fatalf("expected nil resp and found on error")
	}
}

// TestCreateWithGatewayTimeoutRecovery_FindErrorTreatedAsNotFound verifies that errors from find
// are silently ignored and polling continues.
func TestCreateWithGatewayTimeoutRecovery_FindErrorTreatedAsNotFound(t *testing.T) {
	createCalls := 0
	create := func() (*http.Response, error) {
		createCalls++
		if createCalls == 1 {
			return mockResponse(http.StatusGatewayTimeout), nil
		}
		return mockResponse(http.StatusCreated), nil
	}
	find := func() (*fakeResource, error) {
		return nil, errors.New("not found")
	}

	origWindow, origInterval := CreateGatewayTimeoutFindWindow, CreateGatewayTimeoutFindInterval
	CreateGatewayTimeoutFindWindow = 50 * time.Millisecond
	CreateGatewayTimeoutFindInterval = 10 * time.Millisecond
	defer func() {
		CreateGatewayTimeoutFindWindow = origWindow
		CreateGatewayTimeoutFindInterval = origInterval
	}()

	resp, found, err := CreateWithGatewayTimeoutRecovery(create, find)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Fatalf("expected found == nil, got %v", found)
	}
	if resp == nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 on retry after find error")
	}
}
