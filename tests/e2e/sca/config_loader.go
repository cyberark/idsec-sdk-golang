//go:build (e2e && sca) || e2e

package sca

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// LoadSCATestConfig reads the JSON config file and injects auth env vars so
// the existing framework.LoadConfig() picks them up.
//
// Config file resolution:
//  1. IDSEC_E2E_ENV=dev       -> testdata/sca_cli_test_data_dev.json
//  2. IDSEC_E2E_ENV=pre_prod  -> testdata/sca_cli_test_data_pre_prod.json
//  3. default / any other     -> testdata/sca_cli_test_data_prod.json
func LoadSCATestConfig(t *testing.T) map[string]interface{} {
	t.Helper()

	configPath := resolveConfigPath(t)
	require_T(t, configPath != "", "No JSON config file found for selected environment")

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file %s: %v", configPath, err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Failed to parse config file %s: %v", configPath, err)
	}

	t.Logf("Loaded SCA test config from %s", configPath)

	if auth, ok := cfg["auth"].(map[string]interface{}); ok {
		setEnv("IDSEC_E2E_ISP_AUTH_METHOD", strVal(auth, "method"))
		setEnv("IDSEC_E2E_ISP_IDENTITY_URL", strVal(auth, "identity_url"))
	}

	return cfg
}

func skipUnlessSupportedSCAEnv(t *testing.T) {
	t.Helper()

	env := strings.TrimSpace(os.Getenv("IDSEC_E2E_ENV"))
	if env == "" {
		t.Skip("Skipping SCA E2E test: IDSEC_E2E_ENV is not set")
	}
}

func resolveConfigPath(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}

	configFileName := resolveConfigFileName()
	configPath := filepath.Join(filepath.Dir(thisFile), "testdata", configFileName)
	if _, err := os.Stat(configPath); err == nil {
		return configPath
	}

	return ""
}

func resolveConfigFileName() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("IDSEC_E2E_ENV"))) {
	case "dev":
		return "sca_cli_test_data_dev.json"
	case "pre_prod", "pre-prod":
		return "sca_cli_test_data_pre_prod.json"
	default:
		return "sca_cli_test_data_prod.json"
	}
}

// strVal safely extracts a string from a JSON map.
func strVal(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// cspBlock extracts a CSP section (e.g. "azure_cloud_console") from the config.
func cspBlock(cfg map[string]interface{}, key string) map[string]interface{} {
	if block, ok := cfg[key].(map[string]interface{}); ok {
		return block
	}
	return nil
}

// principalBlock extracts the "principal" sub-block from a CSP section.
func principalBlock(section map[string]interface{}) map[string]interface{} {
	if p, ok := section["principal"].(map[string]interface{}); ok {
		return p
	}
	return nil
}

// configTargets extracts the "targets.targets" array from a CSP section.
func configTargets(section map[string]interface{}) []map[string]interface{} {
	targetsBlock, ok := section["targets"].(map[string]interface{})
	if !ok {
		return nil
	}
	targetsList, ok := targetsBlock["targets"].([]interface{})
	if !ok {
		return nil
	}
	var result []map[string]interface{}
	for _, item := range targetsList {
		if m, ok := item.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

func setEnv(key, value string) {
	if value != "" {
		os.Setenv(key, value)
	}
}

func require_T(t *testing.T, cond bool, msg string) {
	t.Helper()
	if !cond {
		t.Fatal(msg)
	}
}
