//go:build e2e

package framework

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// RandomResourceName generates a unique resource name with the given prefix.
// The name follows the pattern: prefix-randomstring (e.g., "e2e-connector-abc123").
//
// For multi-tenant environments, include tenant/namespace in the prefix:
//
//	framework.RandomResourceName("tenant1-e2e-connector")
//
// Note: Namespace is optional in the SDK; developers can use flat naming if preferred.
// The random suffix ensures uniqueness across concurrent test runs.
func RandomResourceName(prefix string) string {
	// Generate a random 8-character string
	randomSuffix := strings.ToLower(common.RandomString(8))
	return fmt.Sprintf("%s-%s", prefix, randomSuffix)
}

// WaitForCondition polls a condition function until it returns true or the timeout is reached.
// It checks the condition at the specified interval.
//
// Parameters:
//   - timeout: Maximum time to wait for the condition
//   - interval: Time between condition checks
//   - conditionFn: Function that returns true when the condition is met, or an error
//
// Returns an error if the timeout is reached or if the condition function returns an error.
func WaitForCondition(timeout, interval time.Duration, conditionFn func() (bool, error)) error {
	deadline := time.Now().Add(timeout)

	for {
		// Check if we've exceeded the timeout
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout after %v waiting for condition", timeout)
		}

		// Check the condition
		met, err := conditionFn()
		if err != nil {
			return fmt.Errorf("condition check failed: %w", err)
		}

		if met {
			return nil
		}

		// Wait before next check
		time.Sleep(interval)
	}
}

// RequireNoError is a convenience wrapper around testing.T that fails the test
// with a formatted message if the error is not nil.
func RequireNoError(t *testing.T, err error, msgFormat string, args ...interface{}) {
	t.Helper()
	if err != nil {
		msg := fmt.Sprintf(msgFormat, args...)
		t.Fatalf("%s: %v", msg, err)
	}
}

// AssertNoError is similar to RequireNoError but uses Error instead of Fatal,
// allowing the test to continue.
func AssertNoError(t *testing.T, err error, msgFormat string, args ...interface{}) {
	t.Helper()
	if err != nil {
		msg := fmt.Sprintf(msgFormat, args...)
		t.Errorf("%s: %v", msg, err)
	}
}

// RetryOperation retries an operation up to maxAttempts times with a delay between attempts.
// It returns the result of the first successful attempt or the last error if all attempts fail.
func RetryOperation(maxAttempts int, delay time.Duration, operation func() error) error {
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err

		if attempt < maxAttempts {
			time.Sleep(delay)
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, lastErr)
}

// LogSection prints a formatted section header in test logs for better readability.
func LogSection(t *testing.T, title string) {
	t.Helper()
	separator := strings.Repeat("=", 60)
	t.Logf("\n%s\n  %s\n%s", separator, title, separator)
}
