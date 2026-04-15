// Copyright (c) CyberArk.
// SPDX-License-Identifier: Apache-2.0

package featureadoption

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

func TestCollectCommonMetrics(t *testing.T) {
	metrics := collectTelemetryMetrics()

	require.Len(t, metrics, 3, "collectTelemetryMetrics should return exactly 3 collectors (metadata, env, os)")

	// First: metadata
	assert.Equal(t, collectors.IdsecMetadataMetricsCollectorName, metrics[0].Collector)
	assert.NotEmpty(t, metrics[0].Metrics, "metadata metrics should not be empty")
	metricNames := make(map[string]bool)
	for _, m := range metrics[0].Metrics {
		metricNames[m.Name] = true
	}
	assert.True(t, metricNames["idsec_tool"], "metadata should contain idsec_tool")

	// Second: environment
	assert.Equal(t, collectors.IdsecEnvironmentMetricsCollectorName, metrics[1].Collector)
	assert.NotEmpty(t, metrics[1].Metrics, "environment metrics should not be empty")

	// Third: os
	assert.Equal(t, collectors.IdsecOSMetricsCollectorName, metrics[2].Collector)
	assert.NotEmpty(t, metrics[2].Metrics, "os metrics should not be empty")
}
