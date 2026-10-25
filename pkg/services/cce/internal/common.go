package internal

import (
	"encoding/json"
	"errors"
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

// APIError represents a non-2xx response from the CCE API.
// Message holds the human-readable reason taken from the response body;
// Body keeps the raw response for callers that need it.
type APIError struct {
	Context      string
	StatusCode   int
	AppErrorCode string
	Message      string
	Body         string
}

// Error renders the error as "<context>: <message> (HTTP <code> <status>, <app_error_code>)".
func (e *APIError) Error() string {
	status := fmt.Sprintf("HTTP %d", e.StatusCode)
	if text := http.StatusText(e.StatusCode); text != "" {
		status += " " + text
	}
	if e.AppErrorCode != "" {
		status += ", " + e.AppErrorCode
	}
	if e.Message == "" {
		return fmt.Sprintf("%s (%s)", e.Context, status)
	}
	return fmt.Sprintf("%s: %s (%s)", e.Context, e.Message, status)
}

// NewAPIError builds an APIError from a CCE error response body.
// The message is taken from "description", falling back to "message",
// and then to the raw body when neither is present or the body is not a JSON object.
func NewAPIError(statusCode int, body []byte, context string) *APIError {
	apiErr := &APIError{
		Context:    context,
		StatusCode: statusCode,
		Body:       string(body),
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err == nil {
		apiErr.AppErrorCode = stringField(parsed, "app_error_code")
		apiErr.Message = stringField(parsed, "description")
		if apiErr.Message == "" {
			apiErr.Message = stringField(parsed, "message")
		}
	}
	if apiErr.Message == "" {
		apiErr.Message = strings.TrimSpace(string(body))
	}
	return apiErr
}

// stringField returns a string field of a decoded JSON object, or the compact JSON
// of a non-string value. Missing and null fields yield an empty string.
func stringField(fields map[string]interface{}, key string) string {
	value, ok := fields[key]
	if !ok || value == nil {
		return ""
	}
	if s, ok := value.(string); ok {
		return strings.TrimSpace(s)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}

// AsAPIError returns the APIError wrapped in err, if any.
func AsAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}

// HandleNon2xxResponse reads a non-2xx response body and returns it as an *APIError.
// The raw body is logged for troubleshooting; the returned error carries the readable message.
func HandleNon2xxResponse(logger *common.IdsecLogger, statusCode int, body io.ReadCloser, context string) error {
	data, err := io.ReadAll(body)
	if err != nil {
		logger.Warning("Failed to read non-2xx response body: %v", err)
	}
	logger.Error("Non-2xx HTTP response: %s - status code: %d - %s", context, statusCode, string(data))
	return NewAPIError(statusCode, data, context)
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
