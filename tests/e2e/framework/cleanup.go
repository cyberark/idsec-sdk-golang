//go:build e2e

package framework

import (
	"fmt"
	"sync"
	"testing"
)

// CleanupFunc represents a cleanup function with a descriptive name.
type CleanupFunc struct {
	Name string
	Fn   func() error
}

// CleanupStack manages a LIFO stack of cleanup functions that need to be executed.
// It ensures that resources are cleaned up in reverse order of creation, even if some cleanups fail.
// Cleanup failures are tracked and reported at the end of cleanup execution.
type CleanupStack struct {
	mu          sync.Mutex
	funcs       []CleanupFunc
	t           *testing.T
	errors      []error // Track cleanup failures for reporting
	failOnError bool    // If true, test fails on cleanup errors; if false, only logs warnings
}

// NewCleanupStack creates a new cleanup stack for the given test.
// By default, cleanup errors will cause the test to fail.
// Use SetFailOnError(false) to only log warnings instead of failing the test.
func NewCleanupStack(t *testing.T) *CleanupStack {
	return &CleanupStack{
		funcs:       make([]CleanupFunc, 0),
		t:           t,
		errors:      make([]error, 0),
		failOnError: true, // Default: fail test on cleanup errors
	}
}

// Push adds a cleanup function to the stack.
// The function will be executed in LIFO order (last pushed, first executed).
func (s *CleanupStack) Push(name string, fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.funcs = append(s.funcs, CleanupFunc{
		Name: name,
		Fn:   fn,
	})

	s.t.Logf("Registered cleanup: %s", name)
}

// ExecuteAll runs all cleanup functions in reverse order (LIFO).
// It continues executing all cleanups even if some fail, collecting errors along the way.
// After all cleanups are attempted, any failures are reported based on the failOnError setting:
// - If failOnError is true (default), failures are reported via t.Errorf() and the test fails.
// - If failOnError is false, failures are only logged as warnings via t.Logf().
// This ensures maximum cleanup even in failure scenarios while allowing control over test failure behavior.
func (s *CleanupStack) ExecuteAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.funcs) == 0 {
		return
	}

	s.t.Log("Starting cleanup...")

	// Execute in reverse order (LIFO)
	for i := len(s.funcs) - 1; i >= 0; i-- {
		cleanup := s.funcs[i]
		s.t.Logf("Executing cleanup: %s", cleanup.Name)

		if err := cleanup.Fn(); err != nil {
			// Collect error and continue with remaining cleanups
			cleanupErr := fmt.Errorf("cleanup failed for %s: %w", cleanup.Name, err)
			s.errors = append(s.errors, cleanupErr)
			s.t.Logf("WARNING: %v", cleanupErr)
		} else {
			s.t.Logf("Successfully cleaned up: %s", cleanup.Name)
		}
	}

	// Report aggregated cleanup failures
	if len(s.errors) > 0 {
		if s.failOnError {
			s.t.Errorf("Cleanup had %d failure(s):", len(s.errors))
			for _, err := range s.errors {
				s.t.Errorf("  - %v", err)
			}
		} else {
			s.t.Logf("WARNING: Cleanup had %d failure(s) (test will not fail):", len(s.errors))
			for _, err := range s.errors {
				s.t.Logf("  - %v", err)
			}
		}
	}

	s.t.Log("Cleanup complete")
}

// Count returns the number of cleanup functions registered.
func (s *CleanupStack) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.funcs)
}

// Clear removes all cleanup functions without executing them.
// This should only be used in exceptional cases.
func (s *CleanupStack) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.funcs = make([]CleanupFunc, 0)
}

// TrackResource is a convenience wrapper that creates a cleanup function
// with a formatted name and registers it.
func (s *CleanupStack) TrackResource(resourceType, resourceID string, cleanupFn func() error) {
	name := fmt.Sprintf("%s: %s", resourceType, resourceID)
	s.Push(name, cleanupFn)
}

// HasErrors returns true if any cleanup functions failed during ExecuteAll.
func (s *CleanupStack) HasErrors() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.errors) > 0
}

// Errors returns all errors that occurred during cleanup execution.
func (s *CleanupStack) Errors() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Return a copy to prevent external modification
	result := make([]error, len(s.errors))
	copy(result, s.errors)
	return result
}

// SetFailOnError configures whether cleanup errors should cause the test to fail.
// If set to true (default), cleanup errors will cause the test to fail via t.Errorf().
// If set to false, cleanup errors will only be logged as warnings via t.Logf().
func (s *CleanupStack) SetFailOnError(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failOnError = fail
}
