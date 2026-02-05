// Package common provides shared utilities and types for the IDSEC SDK.
package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IdsecClientRetryChainMode defines how strategies in a chain are evaluated.
type IdsecClientRetryChainMode int

const (
	// RetryChainModeOR evaluates strategies until one returns true (logical OR).
	// The request is retried if at least one strategy decides to retry.
	RetryChainModeOR IdsecClientRetryChainMode = iota

	// RetryChainModeAND evaluates all strategies and requires all to return true (logical AND).
	// The request is retried only if all strategies decide to retry.
	RetryChainModeAND
)

// IdsecClientRetryStrategy defines the interface for retry strategies.
//
// Implementations of this interface can configure an IdsecClient with custom
// retry behavior. The strategy determines when and how many times to retry
// failed HTTP requests based on the response characteristics.
type IdsecClientRetryStrategy interface {
	// ConfigureClient configures the given IdsecClient with the retry strategy.
	//
	// This method sets up the retry callback and retry count on the client
	// according to the strategy's logic.
	//
	// Parameters:
	//   - client: The IdsecClient instance to configure
	ConfigureClient(client *IdsecClient)
}

// IdsecClientDefaultRetryStrategy is a no-op retry strategy that does not retry requests.
//
// This strategy disables retry behavior by not setting any retry callback.
// It's useful as a default or when you want to explicitly disable retries.
type IdsecClientDefaultRetryStrategy struct{}

// ConfigureClient configures the client to not retry any requests.
//
// Parameters:
//   - client: The IdsecClient instance to configure
//
// Example:
//
//	strategy := &DefaultRetryStrategy{}
//	strategy.ConfigureClient(client)
func (s *IdsecClientDefaultRetryStrategy) ConfigureClient(client *IdsecClient) {
	client.SetRetry(nil, 1)
}

// IdsecClientRetryAllErrorsStrategy retries on any server error (5xx status codes).
//
// This strategy will retry any request that returns a status code >= 500.
// It's useful for handling transient server errors.
type IdsecClientRetryAllErrorsStrategy struct {
	MaxRetries int
}

// ConfigureClient configures the client to retry on all server errors.
//
// Parameters:
//   - client: The IdsecClient instance to configure
//
// Example:
//
//	strategy := &RetryAllErrorsStrategy{MaxRetries: 3}
//	strategy.ConfigureClient(client)
func (s *IdsecClientRetryAllErrorsStrategy) ConfigureClient(client *IdsecClient) {
	client.SetRetry(func(c *IdsecClient, req *http.Request, resp *http.Response) bool {
		return resp.StatusCode >= http.StatusInternalServerError
	}, s.MaxRetries)
}

// IdsecClientRetryBodyErrorsStrategy retries based on error strings found in the response body.
//
// This strategy reads the response body and checks if it contains any of the
// specified error strings. If a match is found, the request is retried.
// Only applies to server errors (5xx status codes).
type IdsecClientRetryBodyErrorsStrategy struct {
	MaxRetries    int
	ErrorStrings  []string
	CaseSensitive bool
	logger        *IdsecLogger
}

// ConfigureClient configures the client to retry based on response body content.
//
// Parameters:
//   - client: The IdsecClient instance to configure
//
// Example:
//
//	strategy := &RetryBodyErrorsStrategy{
//	    MaxRetries:     3,
//	    ErrorStrings:   []string{"timeout", "unavailable"},
//	    CaseSensitive:  false,
//	}
//	strategy.ConfigureClient(client)
func (s *IdsecClientRetryBodyErrorsStrategy) ConfigureClient(client *IdsecClient) {
	client.SetRetry(func(c *IdsecClient, req *http.Request, resp *http.Response) bool {
		s.logger.Info("RetryBodyErrorsStrategy: checking response body for error strings")
		if resp.StatusCode < http.StatusInternalServerError {
			return false
		}

		if len(s.ErrorStrings) == 0 {
			return false
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(strings.NewReader(string(body)))

		bodyStr := string(body)
		if !s.CaseSensitive {
			bodyStr = strings.ToLower(bodyStr)
		}

		for _, errorStr := range s.ErrorStrings {
			searchStr := errorStr
			if !s.CaseSensitive {
				searchStr = strings.ToLower(errorStr)
			}
			if strings.Contains(bodyStr, searchStr) {
				s.logger.Info("RetryBodyErrorsStrategy: response body contains error string '%s' - retrying", errorStr)
				return true
			}
		}
		s.logger.Info("RetryBodyErrorsStrategy: no matching error strings found in response body")
		return false
	}, s.MaxRetries)
}

// IdsecClientRetryHeaderErrorsStrategy retries based on specific header values in the response.
//
// This strategy checks response headers for specific key-value pairs.
// If any of the specified headers match the expected values, the request is retried.
// Only applies to server errors (5xx status codes).
type IdsecClientRetryHeaderErrorsStrategy struct {
	MaxRetries    int
	HeaderErrors  map[string]string
	CaseSensitive bool
	logger        *IdsecLogger
}

// ConfigureClient configures the client to retry based on response headers.
//
// Parameters:
//   - client: The IdsecClient instance to configure
//
// Example:
//
//	strategy := &RetryHeaderErrorsStrategy{
//	    MaxRetries: 3,
//	    HeaderErrors: map[string]string{
//	        "X-Error-Type": "transient",
//	        "Retry-After":  "true",
//	    },
//	    CaseSensitive: false,
//	}
//	strategy.ConfigureClient(client)
func (s *IdsecClientRetryHeaderErrorsStrategy) ConfigureClient(client *IdsecClient) {
	client.SetRetry(func(c *IdsecClient, req *http.Request, resp *http.Response) bool {
		if resp.StatusCode < http.StatusInternalServerError {
			return false
		}

		if len(s.HeaderErrors) == 0 {
			return false
		}

		for headerName, expectedValue := range s.HeaderErrors {
			actualValue := resp.Header.Get(headerName)
			if actualValue == "" {
				continue
			}

			compareActual := actualValue
			compareExpected := expectedValue
			if !s.CaseSensitive {
				compareActual = strings.ToLower(actualValue)
				compareExpected = strings.ToLower(expectedValue)
			}

			if compareActual == compareExpected {
				s.logger.Info("RetryHeaderErrorsStrategy: header %s has value %s, expected %s - retrying", headerName, actualValue, expectedValue)
				return true
			}
		}

		return false
	}, s.MaxRetries)
}

// IdsecClientRetryStatusCodesStrategy retries on specific HTTP status codes.
//
// This strategy provides fine-grained control over which status codes
// should trigger a retry. Useful when you want to retry only on specific
// error conditions rather than all 5xx errors.
type IdsecClientRetryStatusCodesStrategy struct {
	MaxRetries  int
	StatusCodes []int
}

// ConfigureClient configures the client to retry on specific status codes.
//
// Parameters:
//   - client: The IdsecClient instance to configure
//
// Example:
//
//	strategy := &RetryStatusCodesStrategy{
//	    MaxRetries:  3,
//	    StatusCodes: []int{500, 502, 503, 504},
//	}
//	strategy.ConfigureClient(client)
func (s *IdsecClientRetryStatusCodesStrategy) ConfigureClient(client *IdsecClient) {
	client.SetRetry(func(c *IdsecClient, req *http.Request, resp *http.Response) bool {
		if len(s.StatusCodes) == 0 {
			return false
		}

		for _, code := range s.StatusCodes {
			if resp.StatusCode == code {
				return true
			}
		}

		return false
	}, s.MaxRetries)
}

// IdsecClientRetryWithBackoffStrategy retries with exponential backoff and optional jitter.
//
// This strategy wraps another retry strategy and adds intelligent backoff
// behavior between retry attempts. It uses exponential backoff to gradually
// increase the delay between retries, with optional jitter to prevent
// thundering herd problems.
//
// Note: This strategy maintains internal state to track retry attempts per request.
// The request is uniquely identified by a hash of the URL and request body.
// The attempts map is cleaned up when retries complete for a given request.
type IdsecClientRetryWithBackoffStrategy struct {
	BaseStrategy IdsecClientRetryStrategy
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       bool
	attemptsMap  map[string]int
	mu           sync.Mutex
	logger       *IdsecLogger
}

// ConfigureClient configures the client with the base strategy and adds backoff logic.
//
// Note: The backoff delays are applied before each retry attempt. The actual
// retry decision logic is delegated to the BaseStrategy. The attempt counter
// is tracked per-request using a hash of the URL and body, and cleaned up when
// retries complete.
//
// Parameters:
//   - client: The IdsecClient instance to configure
//
// Example:
//
//	baseStrategy := &RetryAllErrorsStrategy{MaxRetries: 3}
//	strategy := &RetryWithBackoffStrategy{
//	    BaseStrategy: baseStrategy,
//	    InitialDelay: 1 * time.Second,
//	    MaxDelay:     30 * time.Second,
//	    Multiplier:   2.0,
//	    Jitter:       true,
//	}
//	strategy.ConfigureClient(client)
func (s *IdsecClientRetryWithBackoffStrategy) ConfigureClient(client *IdsecClient) {
	if s.BaseStrategy == nil {
		s.BaseStrategy = &IdsecClientDefaultRetryStrategy{}
	}
	if s.attemptsMap == nil {
		s.attemptsMap = make(map[string]int)
	}
	s.BaseStrategy.ConfigureClient(client)
	originalCallback := client.retryCallback
	if originalCallback == nil {
		return
	}

	client.SetRetry(func(c *IdsecClient, req *http.Request, resp *http.Response) bool {
		shouldRetry := originalCallback(c, req, resp)
		requestKey := s.getRequestKey(req)

		s.mu.Lock()
		defer s.mu.Unlock()

		if !shouldRetry {
			delete(s.attemptsMap, requestKey)
			return false
		}

		attemptCount := s.attemptsMap[requestKey]

		// Apply backoff delay before retrying (skip on first attempt)
		s.logger.Info("RetryWithBackoffStrategy: attempt %d for request hash %s", attemptCount+1, requestKey)
		if attemptCount > 0 {
			delay := s.InitialDelay
			for i := 1; i < attemptCount; i++ {
				delay = time.Duration(float64(delay) * s.Multiplier)
				if delay > s.MaxDelay {
					delay = s.MaxDelay
					break
				}
			}

			if s.Jitter {
				delay = s.getJitteredDuration(delay)
			}

			// Release lock before sleeping to avoid blocking other requests
			s.mu.Unlock()
			s.logger.Info("RetryWithBackoffStrategy: sleeping for %s before retrying request hash %s", delay.String(), requestKey)
			time.Sleep(delay)
			s.mu.Lock()
		}
		s.attemptsMap[requestKey]++
		return true
	}, client.retryCount)
}

// getRequestKey generates a unique key for a request based on URL and body.
//
// This method creates a SHA-256 hash of the request URL and body combined.
// The hash ensures that identical requests are tracked together while different
// requests (even to the same URL with different bodies) are tracked separately.
//
// Parameters:
//   - req: The HTTP request to generate a key for
//
// Returns a hex-encoded hash string representing the unique request.
func (s *IdsecClientRetryWithBackoffStrategy) getRequestKey(req *http.Request) string {
	hasher := sha256.New()
	hasher.Write([]byte(req.URL.String()))
	hasher.Write([]byte(req.Method))
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			hasher.Write(bodyBytes)
			req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// getJitteredDuration applies random jitter to a duration.
//
// This function takes a base duration and returns a jittered version of it
// by adding a random value between 0 and 50% of the base duration. This helps
// prevent thundering herd problems where multiple clients retry at exactly
// the same time.
//
// The jitter is calculated as: duration + random(0, duration * 0.5)
// Uses crypto/rand for cryptographically secure random number generation.
//
// Parameters:
//   - duration: The base duration to apply jitter to
//
// Returns a new duration with random jitter applied.
//
// Example:
//
//	baseDelay := 1 * time.Second
//	jitteredDelay := getJitteredDuration(baseDelay)
//	// jitteredDelay will be between 1s and 1.5s
func (s *IdsecClientRetryWithBackoffStrategy) getJitteredDuration(duration time.Duration) time.Duration {
	maxJitter := int64(float64(duration) * 0.5)
	if maxJitter <= 0 {
		return duration
	}

	n, err := rand.Int(rand.Reader, big.NewInt(maxJitter))
	if err != nil {
		return duration
	}

	jitter := time.Duration(n.Int64())
	return duration + jitter
}

// IdsecClientRetryChainStrategy chains multiple retry strategies together.
//
// This strategy allows you to combine multiple retry strategies in a chain.
// When a request fails, the chain evaluates strategies according to the ChainMode:
// - OR mode: Retries if at least one strategy decides to retry (default)
// - AND mode: Retries only if all strategies decide to retry
//
// This is useful for implementing fallback retry logic or requiring multiple
// conditions to be met before retrying.
//
// Note: The MaxRetries field determines the overall maximum number of retry attempts
// across all strategies in the chain. Each individual strategy's MaxRetries is ignored.
type IdsecClientRetryChainStrategy struct {
	MaxRetries int
	Strategies []IdsecClientRetryStrategy
	ChainMode  IdsecClientRetryChainMode
	logger     *IdsecLogger
}

// ConfigureClient configures the client to use chained retry strategies.
//
// The chain evaluates each strategy's retry callback according to ChainMode:
// - OR mode: Stops and returns true as soon as one strategy returns true
// - AND mode: Evaluates all strategies and returns true only if all return true
//
// Parameters:
//   - client: The IdsecClient instance to configure
//
// Example (OR mode):
//
//	chain := &RetryChainStrategy{
//	    MaxRetries: 5,
//	    ChainMode:  RetryChainModeOR,
//	    Strategies: []IdsecClientRetryStrategy{
//	        NewRetryStatusCodesStrategy(0, []int{503, 504}),
//	        NewRetryBodyErrorsStrategy(0, []string{"timeout"}, false),
//	    },
//	}
//	chain.ConfigureClient(client)
//
// Example (AND mode):
//
//	chain := &RetryChainStrategy{
//	    MaxRetries: 5,
//	    ChainMode:  RetryChainModeAND,
//	    Strategies: []IdsecClientRetryStrategy{
//	        NewRetryStatusCodesStrategy(0, []int{503}),
//	        NewRetryBodyErrorsStrategy(0, []string{"retry"}, false),
//	    },
//	}
//	chain.ConfigureClient(client)
func (s *IdsecClientRetryChainStrategy) ConfigureClient(client *IdsecClient) {
	if len(s.Strategies) == 0 {
		client.SetRetry(nil, 1)
		return
	}
	var callbacks []func(*IdsecClient, *http.Request, *http.Response) bool
	for i, strategy := range s.Strategies {
		tempClient := &IdsecClient{}
		strategy.ConfigureClient(tempClient)
		if tempClient.retryCallback != nil {
			callbacks = append(callbacks, tempClient.retryCallback)
			s.logger.Debug("RetryChainStrategy: added strategy %d to chain", i)
		}
	}

	if len(callbacks) == 0 {
		client.SetRetry(nil, 1)
		return
	}

	if s.ChainMode == RetryChainModeAND {
		client.SetRetry(func(c *IdsecClient, req *http.Request, resp *http.Response) bool {
			s.logger.Info("RetryChainStrategy (AND): evaluating %d strategies for request", len(callbacks))
			for i, callback := range callbacks {
				if !callback(c, req, resp) {
					s.logger.Info("RetryChainStrategy (AND): strategy %d decided not to retry, returning false", i)
					return false
				}
			}
			s.logger.Info("RetryChainStrategy (AND): all strategies decided to retry")
			return true
		}, s.MaxRetries)
	} else {
		client.SetRetry(func(c *IdsecClient, req *http.Request, resp *http.Response) bool {
			s.logger.Info("RetryChainStrategy (OR): evaluating %d strategies for request", len(callbacks))
			for i, callback := range callbacks {
				if callback(c, req, resp) {
					s.logger.Info("RetryChainStrategy (OR): strategy %d decided to retry", i)
					return true
				}
			}
			s.logger.Info("RetryChainStrategy (OR): no strategy decided to retry")
			return false
		}, s.MaxRetries)
	}
}

// NewDefaultRetryStrategy creates a new DefaultRetryStrategy instance.
//
// This constructor creates a retry strategy that does not retry any requests.
// It's useful as a default or when you want to explicitly disable retries.
//
// Returns a new DefaultRetryStrategy instance.
//
// Example:
//
//	strategy := NewDefaultRetryStrategy()
//	strategy.ConfigureClient(client)
func NewDefaultRetryStrategy() *IdsecClientDefaultRetryStrategy {
	return &IdsecClientDefaultRetryStrategy{}
}

// NewRetryAllErrorsStrategy creates a new RetryAllErrorsStrategy instance.
//
// This constructor creates a retry strategy that retries on any server error
// (5xx status codes). It's useful for handling transient server errors.
//
// Parameters:
//   - maxRetries: The maximum number of retry attempts
//
// Returns a new RetryAllErrorsStrategy instance.
//
// Example:
//
//	strategy := NewRetryAllErrorsStrategy(3)
//	strategy.ConfigureClient(client)
func NewRetryAllErrorsStrategy(maxRetries int) *IdsecClientRetryAllErrorsStrategy {
	return &IdsecClientRetryAllErrorsStrategy{
		MaxRetries: maxRetries,
	}
}

// NewRetryBodyErrorsStrategy creates a new RetryBodyErrorsStrategy instance.
//
// This constructor creates a retry strategy that retries based on error strings
// found in the response body. Only applies to server errors (5xx status codes).
//
// Parameters:
//   - maxRetries: The maximum number of retry attempts
//   - errorStrings: The list of error strings to check for in the response body
//   - caseSensitive: Whether the error string matching is case-sensitive
//
// Returns a new RetryBodyErrorsStrategy instance.
//
// Example:
//
//	strategy := NewRetryBodyErrorsStrategy(3, []string{"timeout", "unavailable"}, false)
//	strategy.ConfigureClient(client)
func NewRetryBodyErrorsStrategy(maxRetries int, errorStrings []string, caseSensitive bool) *IdsecClientRetryBodyErrorsStrategy {
	return &IdsecClientRetryBodyErrorsStrategy{
		MaxRetries:    maxRetries,
		ErrorStrings:  errorStrings,
		CaseSensitive: caseSensitive,
		logger:        GetLogger("RetryBodyErrorsStrategy", Unknown),
	}
}

// NewRetryHeaderErrorsStrategy creates a new RetryHeaderErrorsStrategy instance.
//
// This constructor creates a retry strategy that retries based on specific header
// values in the response. Only applies to server errors (5xx status codes).
//
// Parameters:
//   - maxRetries: The maximum number of retry attempts
//   - headerErrors: Map of header names to expected error values
//   - caseSensitive: Whether the header value matching is case-sensitive
//
// Returns a new RetryHeaderErrorsStrategy instance.
//
// Example:
//
//	headerErrors := map[string]string{
//	    "X-Error-Type": "transient",
//	    "Retry-After":  "true",
//	}
//	strategy := NewRetryHeaderErrorsStrategy(3, headerErrors, false)
//	strategy.ConfigureClient(client)
func NewRetryHeaderErrorsStrategy(maxRetries int, headerErrors map[string]string, caseSensitive bool) *IdsecClientRetryHeaderErrorsStrategy {
	return &IdsecClientRetryHeaderErrorsStrategy{
		MaxRetries:    maxRetries,
		HeaderErrors:  headerErrors,
		CaseSensitive: caseSensitive,
		logger:        GetLogger("RetryHeaderErrorsStrategy", Unknown),
	}
}

// NewRetryStatusCodesStrategy creates a new RetryStatusCodesStrategy instance.
//
// This constructor creates a retry strategy that retries on specific HTTP status codes.
// It provides fine-grained control over which status codes should trigger a retry.
//
// Parameters:
//   - maxRetries: The maximum number of retry attempts
//   - statusCodes: The list of HTTP status codes that should trigger a retry
//
// Returns a new RetryStatusCodesStrategy instance.
//
// Example:
//
//	strategy := NewRetryStatusCodesStrategy(3, []int{500, 502, 503, 504})
//	strategy.ConfigureClient(client)
func NewRetryStatusCodesStrategy(maxRetries int, statusCodes []int) *IdsecClientRetryStatusCodesStrategy {
	return &IdsecClientRetryStatusCodesStrategy{
		MaxRetries:  maxRetries,
		StatusCodes: statusCodes,
	}
}

// NewRetryWithBackoffStrategy creates a new RetryWithBackoffStrategy instance.
//
// This constructor creates a retry strategy that wraps another retry strategy
// and adds exponential backoff with optional jitter. The backoff behavior helps
// prevent overwhelming the server with rapid retries.
//
// Parameters:
//   - baseStrategy: The underlying retry strategy that determines when to retry
//   - initialDelay: The delay before the first retry attempt
//   - maxDelay: The maximum delay between retry attempts
//   - multiplier: The factor by which the delay increases after each retry
//   - jitter: Whether to enable randomization of delay times
//
// Returns a new RetryWithBackoffStrategy instance.
//
// Example:
//
//	baseStrategy := NewRetryAllErrorsStrategy(3)
//	strategy := NewRetryWithBackoffStrategy(
//	    baseStrategy,
//	    1*time.Second,
//	    30*time.Second,
//	    2.0,
//	    true,
//	)
//	strategy.ConfigureClient(client)
func NewRetryWithBackoffStrategy(baseStrategy IdsecClientRetryStrategy, initialDelay, maxDelay time.Duration, multiplier float64, jitter bool) *IdsecClientRetryWithBackoffStrategy {
	return &IdsecClientRetryWithBackoffStrategy{
		BaseStrategy: baseStrategy,
		InitialDelay: initialDelay,
		MaxDelay:     maxDelay,
		Multiplier:   multiplier,
		Jitter:       jitter,
		attemptsMap:  make(map[string]int),
		logger:       GetLogger("RetryWithBackoffStrategy", Unknown),
	}
}

// NewRetryChainStrategy creates a new RetryChainStrategy instance with OR mode.
//
// This constructor creates a retry strategy that chains multiple strategies together
// using OR logic (at least one strategy must decide to retry). Each strategy in the
// chain is evaluated in order until one decides to retry the request.
// The MaxRetries parameter sets the overall limit for retry attempts across all strategies.
//
// Parameters:
//   - maxRetries: The maximum number of retry attempts across all strategies
//   - strategies: The list of retry strategies to chain together in evaluation order
//
// Returns a new RetryChainStrategy instance with OR mode.
//
// Example:
//
//	strategy := NewRetryChainStrategy(
//	    5,
//	    []IdsecClientRetryStrategy{
//	        NewRetryStatusCodesStrategy(0, []int{503, 504}),
//	        NewRetryBodyErrorsStrategy(0, []string{"timeout"}, false),
//	        NewRetryAllErrorsStrategy(0),
//	    },
//	)
//	strategy.ConfigureClient(client)
func NewRetryChainStrategy(maxRetries int, strategies []IdsecClientRetryStrategy) *IdsecClientRetryChainStrategy {
	return &IdsecClientRetryChainStrategy{
		MaxRetries: maxRetries,
		Strategies: strategies,
		ChainMode:  RetryChainModeOR,
		logger:     GetLogger("RetryChainStrategy", Unknown),
	}
}

// NewRetryChainStrategyWithMode creates a new RetryChainStrategy instance with specified mode.
//
// This constructor creates a retry strategy that chains multiple strategies together
// using the specified ChainMode (AND or OR logic). The mode determines whether all
// strategies must agree to retry (AND) or if at least one strategy is sufficient (OR).
//
// Parameters:
//   - maxRetries: The maximum number of retry attempts across all strategies
//   - strategies: The list of retry strategies to chain together in evaluation order
//   - mode: The chain evaluation mode (RetryChainModeOR or RetryChainModeAND)
//
// Returns a new RetryChainStrategy instance with the specified mode.
//
// Example (OR mode):
//
//	strategy := NewRetryChainStrategyWithMode(
//	    5,
//	    []IdsecClientRetryStrategy{
//	        NewRetryStatusCodesStrategy(0, []int{503, 504}),
//	        NewRetryBodyErrorsStrategy(0, []string{"timeout"}, false),
//	    },
//	    RetryChainModeOR,
//	)
//	strategy.ConfigureClient(client)
//
// Example (AND mode):
//
//	strategy := NewRetryChainStrategyWithMode(
//	    3,
//	    []IdsecClientRetryStrategy{
//	        NewRetryStatusCodesStrategy(0, []int{503}),
//	        NewRetryHeaderErrorsStrategy(0, map[string]string{"X-Retry": "true"}, false),
//	    },
//	    RetryChainModeAND,
//	)
//	strategy.ConfigureClient(client)
func NewRetryChainStrategyWithMode(maxRetries int, strategies []IdsecClientRetryStrategy, mode IdsecClientRetryChainMode) *IdsecClientRetryChainStrategy {
	return &IdsecClientRetryChainStrategy{
		MaxRetries: maxRetries,
		Strategies: strategies,
		ChainMode:  mode,
		logger:     GetLogger("RetryChainStrategy", Unknown),
	}
}
