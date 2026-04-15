//go:build e2e

package e2e

import (
	"os"
	"testing"
)

// TestMain is the entry point for E2E tests.
// It performs global setup and teardown for the entire test suite.
func TestMain(m *testing.M) {
	// Check if we should skip E2E tests
	if skip := os.Getenv("IDSEC_E2E_SKIP"); skip == "true" {
		os.Exit(0)
	}

	// Run tests
	exitCode := m.Run()

	// Exit with the test result code
	os.Exit(exitCode)
}
