// Copyright (c) CyberArk.
// SPDX-License-Identifier: Apache-2.0

package featureadoption

import (
	"fmt"
	"regexp"

	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

// fasTagKeyPattern matches FAS tag key requirements: alphanumeric and underscore only.
var fasTagKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

// sanitizeTagKey converts a metric name to a valid FAS tag key.
// FAS requires keys to match ^[a-zA-Z0-9_]+$. Invalid characters are replaced with underscore.
func sanitizeTagKey(name string) string {
	if name == "" {
		return ""
	}
	if fasTagKeyPattern.MatchString(name) {
		return name
	}
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			result = append(result, c)
		} else {
			// Avoid consecutive underscores
			if len(result) > 0 && result[len(result)-1] != '_' {
				result = append(result, '_')
			}
		}
	}
	// Trim trailing underscore
	for len(result) > 0 && result[len(result)-1] == '_' {
		result = result[:len(result)-1]
	}
	return string(result)
}

// metricsToTags converts IdsecMetrics from collectors into a map suitable for FAS tags.
// Keys are sanitized to match FAS requirements (^[a-zA-Z0-9_]+$). Values are stringified.
// Later metrics with the same key overwrite earlier ones. Internal use only.
func metricsToTags(metricsList []*collectors.IdsecMetrics) map[string]string {
	tags := make(map[string]string)
	for _, m := range metricsList {
		if m == nil {
			continue
		}
		for _, metric := range m.Metrics {
			key := sanitizeTagKey(metric.Name)
			if key == "" {
				continue
			}
			tags[key] = fmt.Sprint(metric.Value)
		}
	}
	return tags
}
