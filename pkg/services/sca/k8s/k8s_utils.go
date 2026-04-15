package k8s

import (
	"fmt"
	"strings"
)

// parseGenerateKubeconfigAllString normalizes all to "true" or "false" for the API. Empty means true.
func parseGenerateKubeconfigAllString(s string) (parsed bool, norm string, err error) {
	trimmed := strings.TrimSpace(s)
	low := strings.ToLower(trimmed)
	if low == "" {
		return true, "true", nil
	}
	switch low {
	case "true":
		return true, "true", nil
	case "false":
		return false, "false", nil
	default:
		return false, "", fmt.Errorf("invalid all value %q; use true or false", trimmed)
	}
}
