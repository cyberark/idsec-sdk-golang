package internal

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// ISP service configuration constants shared across CCE services
const (
	IspServiceName = "cloudonboarding"
	IspVersion     = "."
	IspAPIVersion  = ""
)

// Retry configuration constants shared across CCE services
const (
	DefaultMaxRequestRetries      = 3
	DefaultRequestRetryDelay      = 2 * time.Second
	DefaultRetryDelaySeconds      = 2
	DefaultRetryBackoffMultiplier = 1
)

// IsHTTPSuccess checks if the HTTP status code indicates success (2xx)
func IsHTTPSuccess(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
}

// CloseResponseBody safely closes an HTTP response body with logging
func CloseResponseBody(body io.ReadCloser) {
	if err := body.Close(); err != nil {
		common.GlobalLogger.Warning("Error closing response body: %v", err)
	}
}

// HandleNon2xxResponse creates a formatted error for non-2xx HTTP responses
func HandleNon2xxResponse(logger *common.IdsecLogger, statusCode int, body io.ReadCloser, context string) error {
	responseBody := common.SerializeResponseToJSON(body)
	logger.Error("Non-2xx HTTP response: %s - status code: %d - %s", context, statusCode, responseBody)
	return fmt.Errorf("%s - status code: %d - %s", context, statusCode, responseBody)
}

// IsRetryableError determines if an HTTP error should be retried.
// It returns true for server errors (5xx), rate limits (429), and network errors.
// Client errors (4xx) except rate limits are not retried.
func IsRetryableError(statusCode int, err error) bool {
	// Retry server errors and rate limits
	if statusCode >= http.StatusInternalServerError || statusCode == http.StatusTooManyRequests {
		return true
	}
	// Retry network-related errors
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "connection") ||
			strings.Contains(errStr, "eof") ||
			strings.Contains(errStr, "reset by peer") {
			return true
		}
	}
	return false
}
