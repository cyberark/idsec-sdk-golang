package common

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDefaultRetryStrategy_ConfigureClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		expectedRetryCallback bool
		expectedRetryCount    int
	}{
		{
			name:                  "success_disables_retry",
			expectedRetryCallback: false,
			expectedRetryCount:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("https://example.com")
			strategy := NewDefaultRetryStrategy()

			strategy.ConfigureClient(client)

			if (client.retryCallback != nil) != tt.expectedRetryCallback {
				t.Errorf("Expected retryCallback set=%v, got=%v", tt.expectedRetryCallback, client.retryCallback != nil)
			}
			if client.retryCount != tt.expectedRetryCount {
				t.Errorf("Expected retryCount=%d, got=%d", tt.expectedRetryCount, client.retryCount)
			}
		})
	}
}

func TestRetryAllErrorsStrategy_ConfigureClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		maxRetries         int
		statusCode         int
		expectedRetry      bool
		expectedRetryCount int
	}{
		{
			name:               "success_retries_on_500",
			maxRetries:         3,
			statusCode:         http.StatusInternalServerError,
			expectedRetry:      true,
			expectedRetryCount: 3,
		},
		{
			name:               "success_retries_on_502",
			maxRetries:         5,
			statusCode:         http.StatusBadGateway,
			expectedRetry:      true,
			expectedRetryCount: 5,
		},
		{
			name:               "success_retries_on_503",
			maxRetries:         2,
			statusCode:         http.StatusServiceUnavailable,
			expectedRetry:      true,
			expectedRetryCount: 2,
		},
		{
			name:               "success_no_retry_on_400",
			maxRetries:         3,
			statusCode:         http.StatusBadRequest,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_no_retry_on_404",
			maxRetries:         3,
			statusCode:         http.StatusNotFound,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_no_retry_on_200",
			maxRetries:         3,
			statusCode:         http.StatusOK,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("https://example.com")
			strategy := NewRetryAllErrorsStrategy(tt.maxRetries)

			strategy.ConfigureClient(client)

			if client.retryCallback == nil {
				t.Fatal("Expected retryCallback to be set")
			}
			if client.retryCount != tt.expectedRetryCount {
				t.Errorf("Expected retryCount=%d, got=%d", tt.expectedRetryCount, client.retryCount)
			}

			// Test the callback behavior
			resp := &http.Response{StatusCode: tt.statusCode}
			shouldRetry := client.retryCallback(client, nil, resp)
			if shouldRetry != tt.expectedRetry {
				t.Errorf("Expected shouldRetry=%v for status %d, got=%v", tt.expectedRetry, tt.statusCode, shouldRetry)
			}
		})
	}
}

func TestRetryBodyErrorsStrategy_ConfigureClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		maxRetries         int
		errorStrings       []string
		caseSensitive      bool
		statusCode         int
		responseBody       string
		expectedRetry      bool
		expectedRetryCount int
	}{
		{
			name:               "success_retries_on_matching_body_case_insensitive",
			maxRetries:         3,
			errorStrings:       []string{"timeout", "unavailable"},
			caseSensitive:      false,
			statusCode:         http.StatusInternalServerError,
			responseBody:       `{"error": "Service Unavailable"}`,
			expectedRetry:      true,
			expectedRetryCount: 3,
		},
		{
			name:               "success_retries_on_matching_body_case_sensitive",
			maxRetries:         2,
			errorStrings:       []string{"timeout", "Unavailable"},
			caseSensitive:      true,
			statusCode:         http.StatusServiceUnavailable,
			responseBody:       `{"error": "Service Unavailable"}`,
			expectedRetry:      true,
			expectedRetryCount: 2,
		},
		{
			name:               "success_no_retry_on_non_matching_body",
			maxRetries:         3,
			errorStrings:       []string{"timeout", "unavailable"},
			caseSensitive:      false,
			statusCode:         http.StatusInternalServerError,
			responseBody:       `{"error": "Database error"}`,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_no_retry_on_case_mismatch",
			maxRetries:         3,
			errorStrings:       []string{"Timeout"},
			caseSensitive:      true,
			statusCode:         http.StatusInternalServerError,
			responseBody:       `{"error": "timeout occurred"}`,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_no_retry_on_4xx_even_with_matching_body",
			maxRetries:         3,
			errorStrings:       []string{"timeout"},
			caseSensitive:      false,
			statusCode:         http.StatusBadRequest,
			responseBody:       `{"error": "timeout"}`,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_no_retry_with_empty_error_strings",
			maxRetries:         3,
			errorStrings:       []string{},
			caseSensitive:      false,
			statusCode:         http.StatusInternalServerError,
			responseBody:       `{"error": "timeout"}`,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_partial_match_in_body",
			maxRetries:         3,
			errorStrings:       []string{"time"},
			caseSensitive:      false,
			statusCode:         http.StatusInternalServerError,
			responseBody:       `{"error": "timeout occurred"}`,
			expectedRetry:      true,
			expectedRetryCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("https://example.com")
			strategy := NewRetryBodyErrorsStrategy(tt.maxRetries, tt.errorStrings, tt.caseSensitive)

			strategy.ConfigureClient(client)

			if client.retryCallback == nil {
				t.Fatal("Expected retryCallback to be set")
			}
			if client.retryCount != tt.expectedRetryCount {
				t.Errorf("Expected retryCount=%d, got=%d", tt.expectedRetryCount, client.retryCount)
			}

			// Test the callback behavior
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Body:       io.NopCloser(strings.NewReader(tt.responseBody)),
			}
			shouldRetry := client.retryCallback(client, nil, resp)
			if shouldRetry != tt.expectedRetry {
				t.Errorf("Expected shouldRetry=%v, got=%v", tt.expectedRetry, shouldRetry)
			}

			// Verify body can still be read after callback
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("Expected to be able to read body after callback, got error: %v", err)
			}
			if string(body) != tt.responseBody {
				t.Errorf("Expected body to be preserved, got=%s", string(body))
			}
		})
	}
}

func TestRetryHeaderErrorsStrategy_ConfigureClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		maxRetries         int
		headerErrors       map[string]string
		caseSensitive      bool
		statusCode         int
		responseHeaders    map[string]string
		expectedRetry      bool
		expectedRetryCount int
	}{
		{
			name:       "success_retries_on_matching_header_case_insensitive",
			maxRetries: 3,
			headerErrors: map[string]string{
				"X-Error-Type": "transient",
			},
			caseSensitive: false,
			statusCode:    http.StatusInternalServerError,
			responseHeaders: map[string]string{
				"X-Error-Type": "Transient",
			},
			expectedRetry:      true,
			expectedRetryCount: 3,
		},
		{
			name:       "success_retries_on_matching_header_case_sensitive",
			maxRetries: 2,
			headerErrors: map[string]string{
				"X-Error-Type": "transient",
			},
			caseSensitive: true,
			statusCode:    http.StatusServiceUnavailable,
			responseHeaders: map[string]string{
				"X-Error-Type": "transient",
			},
			expectedRetry:      true,
			expectedRetryCount: 2,
		},
		{
			name:       "success_no_retry_on_non_matching_header",
			maxRetries: 3,
			headerErrors: map[string]string{
				"X-Error-Type": "transient",
			},
			caseSensitive: false,
			statusCode:    http.StatusInternalServerError,
			responseHeaders: map[string]string{
				"X-Error-Type": "permanent",
			},
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:       "success_no_retry_on_case_mismatch",
			maxRetries: 3,
			headerErrors: map[string]string{
				"X-Error-Type": "Transient",
			},
			caseSensitive: true,
			statusCode:    http.StatusInternalServerError,
			responseHeaders: map[string]string{
				"X-Error-Type": "transient",
			},
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:       "success_no_retry_on_missing_header",
			maxRetries: 3,
			headerErrors: map[string]string{
				"X-Error-Type": "transient",
			},
			caseSensitive: false,
			statusCode:    http.StatusInternalServerError,
			responseHeaders: map[string]string{
				"X-Other-Header": "value",
			},
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:       "success_no_retry_on_4xx_even_with_matching_header",
			maxRetries: 3,
			headerErrors: map[string]string{
				"X-Error-Type": "transient",
			},
			caseSensitive: false,
			statusCode:    http.StatusBadRequest,
			responseHeaders: map[string]string{
				"X-Error-Type": "transient",
			},
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_no_retry_with_empty_header_errors",
			maxRetries:         3,
			headerErrors:       map[string]string{},
			caseSensitive:      false,
			statusCode:         http.StatusInternalServerError,
			responseHeaders:    map[string]string{"X-Error-Type": "transient"},
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:       "success_retries_on_multiple_headers_one_matches",
			maxRetries: 3,
			headerErrors: map[string]string{
				"X-Error-Type": "transient",
				"Retry-After":  "true",
			},
			caseSensitive: false,
			statusCode:    http.StatusInternalServerError,
			responseHeaders: map[string]string{
				"X-Error-Type": "permanent",
				"Retry-After":  "true",
			},
			expectedRetry:      true,
			expectedRetryCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("https://example.com")
			strategy := NewRetryHeaderErrorsStrategy(tt.maxRetries, tt.headerErrors, tt.caseSensitive)

			strategy.ConfigureClient(client)

			if client.retryCallback == nil {
				t.Fatal("Expected retryCallback to be set")
			}
			if client.retryCount != tt.expectedRetryCount {
				t.Errorf("Expected retryCount=%d, got=%d", tt.expectedRetryCount, client.retryCount)
			}

			// Test the callback behavior
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			for key, value := range tt.responseHeaders {
				resp.Header.Set(key, value)
			}

			shouldRetry := client.retryCallback(client, nil, resp)
			if shouldRetry != tt.expectedRetry {
				t.Errorf("Expected shouldRetry=%v, got=%v", tt.expectedRetry, shouldRetry)
			}
		})
	}
}

func TestRetryStatusCodesStrategy_ConfigureClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		maxRetries         int
		statusCodes        []int
		responseStatusCode int
		expectedRetry      bool
		expectedRetryCount int
	}{
		{
			name:               "success_retries_on_matching_status_code",
			maxRetries:         3,
			statusCodes:        []int{500, 502, 503},
			responseStatusCode: 502,
			expectedRetry:      true,
			expectedRetryCount: 3,
		},
		{
			name:               "success_retries_on_first_status_code",
			maxRetries:         2,
			statusCodes:        []int{500, 502, 503},
			responseStatusCode: 500,
			expectedRetry:      true,
			expectedRetryCount: 2,
		},
		{
			name:               "success_retries_on_last_status_code",
			maxRetries:         3,
			statusCodes:        []int{500, 502, 503},
			responseStatusCode: 503,
			expectedRetry:      true,
			expectedRetryCount: 3,
		},
		{
			name:               "success_no_retry_on_non_matching_status_code",
			maxRetries:         3,
			statusCodes:        []int{500, 502, 503},
			responseStatusCode: 504,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_no_retry_on_4xx_status_code",
			maxRetries:         3,
			statusCodes:        []int{500, 502, 503},
			responseStatusCode: 404,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_no_retry_with_empty_status_codes",
			maxRetries:         3,
			statusCodes:        []int{},
			responseStatusCode: 500,
			expectedRetry:      false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_retries_on_single_status_code",
			maxRetries:         3,
			statusCodes:        []int{503},
			responseStatusCode: 503,
			expectedRetry:      true,
			expectedRetryCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewSimpleIdsecClient("https://example.com")
			strategy := NewRetryStatusCodesStrategy(tt.maxRetries, tt.statusCodes)

			strategy.ConfigureClient(client)

			if client.retryCallback == nil {
				t.Fatal("Expected retryCallback to be set")
			}
			if client.retryCount != tt.expectedRetryCount {
				t.Errorf("Expected retryCount=%d, got=%d", tt.expectedRetryCount, client.retryCount)
			}

			// Test the callback behavior
			resp := &http.Response{StatusCode: tt.responseStatusCode}
			shouldRetry := client.retryCallback(client, nil, resp)
			if shouldRetry != tt.expectedRetry {
				t.Errorf("Expected shouldRetry=%v for status %d, got=%v", tt.expectedRetry, tt.responseStatusCode, shouldRetry)
			}
		})
	}
}

func TestRetryWithBackoffStrategy_ConfigureClient(t *testing.T) {
	tests := []struct {
		name               string
		baseStrategy       IdsecClientRetryStrategy
		initialDelay       time.Duration
		maxDelay           time.Duration
		multiplier         float64
		jitter             bool
		expectedRetryCount int
	}{
		{
			name:               "success_configures_with_base_strategy",
			baseStrategy:       NewRetryAllErrorsStrategy(3),
			initialDelay:       100 * time.Millisecond,
			maxDelay:           1 * time.Second,
			multiplier:         2.0,
			jitter:             false,
			expectedRetryCount: 3,
		},
		{
			name:               "success_configures_with_jitter",
			baseStrategy:       NewRetryAllErrorsStrategy(2),
			initialDelay:       50 * time.Millisecond,
			maxDelay:           500 * time.Millisecond,
			multiplier:         1.5,
			jitter:             true,
			expectedRetryCount: 2,
		},
		{
			name:               "success_uses_default_strategy_when_nil",
			baseStrategy:       nil,
			initialDelay:       100 * time.Millisecond,
			maxDelay:           1 * time.Second,
			multiplier:         2.0,
			jitter:             false,
			expectedRetryCount: 1, // DefaultRetryStrategy uses 1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewSimpleIdsecClient("https://example.com")
			strategy := NewRetryWithBackoffStrategy(
				tt.baseStrategy,
				tt.initialDelay,
				tt.maxDelay,
				tt.multiplier,
				tt.jitter,
			)

			strategy.ConfigureClient(client)

			if client.retryCount != tt.expectedRetryCount {
				t.Errorf("Expected retryCount=%d, got=%d", tt.expectedRetryCount, client.retryCount)
			}

			// For nil base strategy, callback should be nil after DefaultRetryStrategy
			if tt.baseStrategy == nil && client.retryCallback != nil {
				t.Error("Expected retryCallback to be nil when base strategy is nil (DefaultRetryStrategy)")
			}
		})
	}
}

func TestGetJitteredDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		duration         time.Duration
		minExpected      time.Duration
		maxExpected      time.Duration
		runMultipleTimes bool
	}{
		{
			name:             "success_jitters_one_second",
			duration:         1 * time.Second,
			minExpected:      1 * time.Second,
			maxExpected:      1500 * time.Millisecond,
			runMultipleTimes: true,
		},
		{
			name:             "success_jitters_one_millisecond",
			duration:         1 * time.Millisecond,
			minExpected:      1 * time.Millisecond,
			maxExpected:      1500 * time.Microsecond,
			runMultipleTimes: true,
		},
		{
			name:             "success_jitters_zero_duration",
			duration:         0,
			minExpected:      0,
			maxExpected:      0,
			runMultipleTimes: false,
		},
		{
			name:             "success_jitters_large_duration",
			duration:         1 * time.Minute,
			minExpected:      1 * time.Minute,
			maxExpected:      90 * time.Second,
			runMultipleTimes: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			strategy := NewRetryWithBackoffStrategy(nil, 0, 0, 0, true)
			if tt.runMultipleTimes {
				// Run multiple times to verify randomness and bounds
				for i := 0; i < 10; i++ {
					result := strategy.getJitteredDuration(tt.duration)

					if result < tt.minExpected {
						t.Errorf("Jittered duration %v is less than minimum %v", result, tt.minExpected)
					}
					if result > tt.maxExpected {
						t.Errorf("Jittered duration %v is greater than maximum %v", result, tt.maxExpected)
					}
				}
			} else {
				result := strategy.getJitteredDuration(tt.duration)
				if result != tt.minExpected {
					t.Errorf("Expected jittered duration %v, got %v", tt.minExpected, result)
				}
			}
		})
	}
}

func TestNewDefaultRetryStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{
			name: "success_creates_strategy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			strategy := NewDefaultRetryStrategy()

			if strategy == nil {
				t.Fatal("Expected strategy to be non-nil")
			}
		})
	}
}

func TestNewRetryAllErrorsStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		maxRetries         int
		expectedMaxRetries int
	}{
		{
			name:               "success_creates_strategy_with_max_retries",
			maxRetries:         3,
			expectedMaxRetries: 3,
		},
		{
			name:               "success_creates_strategy_with_zero_retries",
			maxRetries:         0,
			expectedMaxRetries: 0,
		},
		{
			name:               "success_creates_strategy_with_large_retries",
			maxRetries:         100,
			expectedMaxRetries: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			strategy := NewRetryAllErrorsStrategy(tt.maxRetries)

			if strategy == nil {
				t.Fatal("Expected strategy to be non-nil")
			}
			if strategy.MaxRetries != tt.expectedMaxRetries {
				t.Errorf("Expected MaxRetries=%d, got=%d", tt.expectedMaxRetries, strategy.MaxRetries)
			}
		})
	}
}

func TestNewRetryBodyErrorsStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		maxRetries            int
		errorStrings          []string
		caseSensitive         bool
		expectedMaxRetries    int
		expectedErrorStrings  []string
		expectedCaseSensitive bool
	}{
		{
			name:                  "success_creates_strategy_with_all_params",
			maxRetries:            3,
			errorStrings:          []string{"timeout", "unavailable"},
			caseSensitive:         true,
			expectedMaxRetries:    3,
			expectedErrorStrings:  []string{"timeout", "unavailable"},
			expectedCaseSensitive: true,
		},
		{
			name:                  "success_creates_strategy_case_insensitive",
			maxRetries:            2,
			errorStrings:          []string{"error"},
			caseSensitive:         false,
			expectedMaxRetries:    2,
			expectedErrorStrings:  []string{"error"},
			expectedCaseSensitive: false,
		},
		{
			name:                  "success_creates_strategy_with_empty_error_strings",
			maxRetries:            1,
			errorStrings:          []string{},
			caseSensitive:         false,
			expectedMaxRetries:    1,
			expectedErrorStrings:  []string{},
			expectedCaseSensitive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			strategy := NewRetryBodyErrorsStrategy(tt.maxRetries, tt.errorStrings, tt.caseSensitive)

			if strategy == nil {
				t.Fatal("Expected strategy to be non-nil")
			}
			if strategy.MaxRetries != tt.expectedMaxRetries {
				t.Errorf("Expected MaxRetries=%d, got=%d", tt.expectedMaxRetries, strategy.MaxRetries)
			}
			if len(strategy.ErrorStrings) != len(tt.expectedErrorStrings) {
				t.Errorf("Expected ErrorStrings length=%d, got=%d", len(tt.expectedErrorStrings), len(strategy.ErrorStrings))
			}
			if strategy.CaseSensitive != tt.expectedCaseSensitive {
				t.Errorf("Expected CaseSensitive=%v, got=%v", tt.expectedCaseSensitive, strategy.CaseSensitive)
			}
		})
	}
}

func TestNewRetryHeaderErrorsStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		maxRetries            int
		headerErrors          map[string]string
		caseSensitive         bool
		expectedMaxRetries    int
		expectedHeaderErrors  map[string]string
		expectedCaseSensitive bool
	}{
		{
			name:       "success_creates_strategy_with_all_params",
			maxRetries: 3,
			headerErrors: map[string]string{
				"X-Error-Type": "transient",
			},
			caseSensitive:      true,
			expectedMaxRetries: 3,
			expectedHeaderErrors: map[string]string{
				"X-Error-Type": "transient",
			},
			expectedCaseSensitive: true,
		},
		{
			name:       "success_creates_strategy_case_insensitive",
			maxRetries: 2,
			headerErrors: map[string]string{
				"Retry-After": "true",
			},
			caseSensitive:      false,
			expectedMaxRetries: 2,
			expectedHeaderErrors: map[string]string{
				"Retry-After": "true",
			},
			expectedCaseSensitive: false,
		},
		{
			name:                  "success_creates_strategy_with_empty_header_errors",
			maxRetries:            1,
			headerErrors:          map[string]string{},
			caseSensitive:         false,
			expectedMaxRetries:    1,
			expectedHeaderErrors:  map[string]string{},
			expectedCaseSensitive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			strategy := NewRetryHeaderErrorsStrategy(tt.maxRetries, tt.headerErrors, tt.caseSensitive)

			if strategy == nil {
				t.Fatal("Expected strategy to be non-nil")
			}
			if strategy.MaxRetries != tt.expectedMaxRetries {
				t.Errorf("Expected MaxRetries=%d, got=%d", tt.expectedMaxRetries, strategy.MaxRetries)
			}
			if len(strategy.HeaderErrors) != len(tt.expectedHeaderErrors) {
				t.Errorf("Expected HeaderErrors length=%d, got=%d", len(tt.expectedHeaderErrors), len(strategy.HeaderErrors))
			}
			if strategy.CaseSensitive != tt.expectedCaseSensitive {
				t.Errorf("Expected CaseSensitive=%v, got=%v", tt.expectedCaseSensitive, strategy.CaseSensitive)
			}
		})
	}
}

func TestNewRetryStatusCodesStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		maxRetries          int
		statusCodes         []int
		expectedMaxRetries  int
		expectedStatusCodes []int
	}{
		{
			name:                "success_creates_strategy_with_status_codes",
			maxRetries:          3,
			statusCodes:         []int{500, 502, 503},
			expectedMaxRetries:  3,
			expectedStatusCodes: []int{500, 502, 503},
		},
		{
			name:                "success_creates_strategy_with_single_status_code",
			maxRetries:          2,
			statusCodes:         []int{503},
			expectedMaxRetries:  2,
			expectedStatusCodes: []int{503},
		},
		{
			name:                "success_creates_strategy_with_empty_status_codes",
			maxRetries:          1,
			statusCodes:         []int{},
			expectedMaxRetries:  1,
			expectedStatusCodes: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			strategy := NewRetryStatusCodesStrategy(tt.maxRetries, tt.statusCodes)

			if strategy == nil {
				t.Fatal("Expected strategy to be non-nil")
			}
			if strategy.MaxRetries != tt.expectedMaxRetries {
				t.Errorf("Expected MaxRetries=%d, got=%d", tt.expectedMaxRetries, strategy.MaxRetries)
			}
			if len(strategy.StatusCodes) != len(tt.expectedStatusCodes) {
				t.Errorf("Expected StatusCodes length=%d, got=%d", len(tt.expectedStatusCodes), len(strategy.StatusCodes))
			}
		})
	}
}

func TestNewRetryWithBackoffStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		baseStrategy         IdsecClientRetryStrategy
		initialDelay         time.Duration
		maxDelay             time.Duration
		multiplier           float64
		jitter               bool
		expectedInitialDelay time.Duration
		expectedMaxDelay     time.Duration
		expectedMultiplier   float64
		expectedJitter       bool
	}{
		{
			name:                 "success_creates_strategy_with_all_params",
			baseStrategy:         NewRetryAllErrorsStrategy(3),
			initialDelay:         1 * time.Second,
			maxDelay:             30 * time.Second,
			multiplier:           2.0,
			jitter:               true,
			expectedInitialDelay: 1 * time.Second,
			expectedMaxDelay:     30 * time.Second,
			expectedMultiplier:   2.0,
			expectedJitter:       true,
		},
		{
			name:                 "success_creates_strategy_without_jitter",
			baseStrategy:         NewRetryAllErrorsStrategy(2),
			initialDelay:         500 * time.Millisecond,
			maxDelay:             10 * time.Second,
			multiplier:           1.5,
			jitter:               false,
			expectedInitialDelay: 500 * time.Millisecond,
			expectedMaxDelay:     10 * time.Second,
			expectedMultiplier:   1.5,
			expectedJitter:       false,
		},
		{
			name:                 "success_creates_strategy_with_nil_base",
			baseStrategy:         nil,
			initialDelay:         1 * time.Second,
			maxDelay:             5 * time.Second,
			multiplier:           2.0,
			jitter:               true,
			expectedInitialDelay: 1 * time.Second,
			expectedMaxDelay:     5 * time.Second,
			expectedMultiplier:   2.0,
			expectedJitter:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			strategy := NewRetryWithBackoffStrategy(
				tt.baseStrategy,
				tt.initialDelay,
				tt.maxDelay,
				tt.multiplier,
				tt.jitter,
			)

			if strategy == nil {
				t.Fatal("Expected strategy to be non-nil")
			}
			if strategy.InitialDelay != tt.expectedInitialDelay {
				t.Errorf("Expected InitialDelay=%v, got=%v", tt.expectedInitialDelay, strategy.InitialDelay)
			}
			if strategy.MaxDelay != tt.expectedMaxDelay {
				t.Errorf("Expected MaxDelay=%v, got=%v", tt.expectedMaxDelay, strategy.MaxDelay)
			}
			if strategy.Multiplier != tt.expectedMultiplier {
				t.Errorf("Expected Multiplier=%v, got=%v", tt.expectedMultiplier, strategy.Multiplier)
			}
			if strategy.Jitter != tt.expectedJitter {
				t.Errorf("Expected Jitter=%v, got=%v", tt.expectedJitter, strategy.Jitter)
			}
		})
	}
}
