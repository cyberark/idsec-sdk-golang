package common

import (
	"fmt"
	"net/http"
	"time"
)

var (
	// CreateGatewayTimeoutMaxRetries is the number of additional POST attempts made after
	// an initial 504 Gateway Timeout (total attempts = 1 + this value).
	CreateGatewayTimeoutMaxRetries = 3
	// CreateGatewayTimeoutFindWindow is how long to poll for a resource that may have been
	// created despite a 504 before giving up and retrying the creation.
	CreateGatewayTimeoutFindWindow = 5 * time.Second
	// CreateGatewayTimeoutFindInterval is the sleep between poll attempts within the window.
	CreateGatewayTimeoutFindInterval = 1 * time.Second
)

// CreateWithGatewayTimeoutRecovery executes create (a single POST) and handles 504 Gateway
// Timeout responses transparently.
//
// On a 504 the remote may have already persisted the resource while the gateway timed out, so
// find is polled every CreateGatewayTimeoutFindInterval for up to CreateGatewayTimeoutFindWindow.
// Any error from find is treated as "not found yet". If find returns a non-nil result the resource
// is returned immediately and no further POST is attempted.
//
// If find does not locate the resource within the window, create is called again.  This repeats
// up to CreateGatewayTimeoutMaxRetries additional times.  If retries are exhausted the final 504
// response is returned as-is so the caller can produce its standard error.
//
// If a retry POST returns 409 Conflict after a prior 504, find is polled (using the same window)
// because the conflict confirms the original request succeeded. If found the resource is returned;
// if still not found an error is returned.
//
// On any other non-504 response the response is returned unchanged for the caller to handle with
// its existing logic.  On a transport-level error the error is returned immediately.
//
// The caller must close response.Body when found is nil and err is nil; this function closes the
// body for every intermediate 504 (and for a 409-after-504) that leads to a retry or find.
func CreateWithGatewayTimeoutRecovery[T any](
	create func() (*http.Response, error),
	find func() (*T, error),
) (response *http.Response, found *T, err error) {
	hadGatewayTimeout := false
	for attempt := 0; ; attempt++ {
		response, err = create()
		if err != nil {
			return nil, nil, err
		}
		switch response.StatusCode {
		case http.StatusGatewayTimeout:
			hadGatewayTimeout = true
			if attempt >= CreateGatewayTimeoutMaxRetries {
				// Retries exhausted; return the 504 for the caller to produce its error.
				return response, nil, nil
			}
			_ = response.Body.Close()
			if res := findWithinTimeout(find, CreateGatewayTimeoutFindWindow, CreateGatewayTimeoutFindInterval); res != nil {
				return nil, res, nil
			}
			// Resource not found yet; retry the POST.

		case http.StatusConflict:
			if !hadGatewayTimeout {
				// First-attempt 409: let the caller's existing conflict logic handle it.
				return response, nil, nil
			}
			// 409 after a prior 504 means the original request actually succeeded.
			_ = response.Body.Close()
			if res := findWithinTimeout(find, CreateGatewayTimeoutFindWindow, CreateGatewayTimeoutFindInterval); res != nil {
				return nil, res, nil
			}
			return nil, nil, fmt.Errorf("received 409 conflict after gateway timeout but resource could not be found")

		default:
			return response, nil, nil
		}
	}
}

// findWithinTimeout polls find every interval until it returns a non-nil result or the window
// elapses. Any error from find is treated as "not found yet".
func findWithinTimeout[T any](find func() (*T, error), window, interval time.Duration) *T {
	deadline := time.Now().Add(window)
	for {
		if res, err := find(); err == nil && res != nil {
			return res
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		time.Sleep(interval)
	}
}
