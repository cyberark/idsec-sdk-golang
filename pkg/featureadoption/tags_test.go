// Copyright (c) CyberArk.
// SPDX-License-Identifier: Apache-2.0

package featureadoption

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

func TestMetricsToTags(t *testing.T) {
	tests := []struct {
		name        string
		metricsList []*collectors.IdsecMetrics
		want        map[string]string
	}{
		{
			name:        "empty list",
			metricsList: nil,
			want:        map[string]string{},
		},
		{
			name: "single metric",
			metricsList: []*collectors.IdsecMetrics{
				{
					Collector: "metadata",
					Metrics: []collectors.IdsecMetric{
						{Name: "idsec_tool", ShortName: "at", Value: "Idsec-Terraform-Provider"},
					},
				},
			},
			want: map[string]string{"idsec_tool": "Idsec-Terraform-Provider"},
		},
		{
			name: "multiple metrics from multiple collectors",
			metricsList: []*collectors.IdsecMetrics{
				{
					Collector: "metadata",
					Metrics: []collectors.IdsecMetric{
						{Name: "idsec_tool", ShortName: "at", Value: "Idsec-CLI"},
						{Name: "correlation_id", ShortName: "cid", Value: "abc-123"},
					},
				},
				{
					Collector: "os_metrics",
					Metrics: []collectors.IdsecMetric{
						{Name: "os_name", ShortName: "os", Value: "linux"},
						{Name: "architecture", ShortName: "arch", Value: "amd64"},
					},
				},
			},
			want: map[string]string{
				"idsec_tool":     "Idsec-CLI",
				"correlation_id": "abc-123",
				"os_name":        "linux",
				"architecture":   "amd64",
			},
		},
		{
			name: "nil metrics skipped",
			metricsList: []*collectors.IdsecMetrics{
				nil,
				{
					Collector: "metadata",
					Metrics: []collectors.IdsecMetric{
						{Name: "idsec_tool", Value: "test"},
					},
				},
			},
			want: map[string]string{"idsec_tool": "test"},
		},
		{
			name: "non-string values stringified",
			metricsList: []*collectors.IdsecMetrics{
				{
					Collector: "env",
					Metrics: []collectors.IdsecMetric{
						{Name: "proxy_configured", Value: true},
						{Name: "count", Value: 42},
					},
				},
			},
			want: map[string]string{
				"proxy_configured": "true",
				"count":            "42",
			},
		},
		{
			name: "duplicate key overwrites",
			metricsList: []*collectors.IdsecMetrics{
				{
					Collector: "c1",
					Metrics: []collectors.IdsecMetric{
						{Name: "key", Value: "first"},
					},
				},
				{
					Collector: "c2",
					Metrics: []collectors.IdsecMetric{
						{Name: "key", Value: "second"},
					},
				},
			},
			want: map[string]string{"key": "second"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := metricsToTags(tt.metricsList)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMetricsToTags_SanitizesInvalidKeys(t *testing.T) {
	metricsList := []*collectors.IdsecMetrics{
		{
			Collector: "test",
			Metrics: []collectors.IdsecMetric{
				{Name: "valid_key", Value: "v1"},
				{Name: "key-with-dash", Value: "v2"},
				{Name: "key.with.dots", Value: "v3"},
				{Name: "", Value: "skip"},
			},
		},
	}
	got := metricsToTags(metricsList)
	assert.Equal(t, "v1", got["valid_key"])
	assert.Contains(t, got, "key_with_dash")
	assert.Equal(t, "v2", got["key_with_dash"])
	assert.Contains(t, got, "key_with_dots")
	assert.Equal(t, "v3", got["key_with_dots"])
	assert.NotContains(t, got, "")
}
