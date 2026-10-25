//go:build e2e

package framework

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"testing"

	"github.com/joho/godotenv"
)

// suiteEnvFileName is resolved against the working directory, which `go test`
// sets to the directory of the test package being run (the suite).
const suiteEnvFileName = ".env"

var (
	suiteEnvOnce sync.Once
	suiteEnvErr  error
)

// LoadSuiteEnv loads the suite's .env file, if present, into the process environment.
//
// The file is read once per test binary from the package directory of the running
// suite (e.g. tests/e2e/sechub/.env). Variables already set in the environment take
// precedence over values from the file, so CI and shell exports always win.
//
// Suite .env files are committed for non-secret, suite-specific configuration and are
// excluded from the public sync. Never put credentials in them.
func LoadSuiteEnv(t *testing.T) {
	t.Helper()

	suiteEnvOnce.Do(func() {
		suiteEnvErr = loadEnvFile(suiteEnvFileName)
	})
	if suiteEnvErr != nil {
		t.Fatalf("Failed to load suite env file: %v", suiteEnvErr)
	}
}

// loadEnvFile sets variables from the dotenv file at path that are not already set.
// A missing file is not an error.
func loadEnvFile(path string) error {
	envVars, err := godotenv.Read(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	for key, value := range envVars {
		if os.Getenv(key) != "" {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("%s: failed to set %s: %w", path, key, err)
		}
	}
	return nil
}
