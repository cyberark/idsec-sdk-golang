package sca

import "strings"

// SplitCommaSeparated splits a comma-separated string into trimmed, non-empty values.
func SplitCommaSeparated(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
