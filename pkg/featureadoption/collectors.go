// Copyright (c) CyberArk.
// SPDX-License-Identifier: Apache-2.0

package featureadoption

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

// MetadataExtraContext holds a single extra context field for the metadata collector.
// Used by tools (e.g. Terraform provider) to add tool-specific tags to FAS reports.
type MetadataExtraContext struct {
	Name      string
	ShortName string
	Value     string
}

// collectTelemetryMetrics collects metrics from the default telemetry collectors (metadata, env, os).
func collectTelemetryMetrics() []*collectors.IdsecMetrics {
	metadataCollector := collectors.NewIdsecMetadataMetricsCollector().(*collectors.IdsecMetadataMetricsCollector)
	envCollector := collectors.NewIdsecEnvironmentMetricsCollector()
	osCollector := collectors.NewIdsecOSMetricsCollector()

	metadataMetrics, _ := metadataCollector.CollectMetrics()
	envMetrics, _ := envCollector.CollectMetrics()
	osMetrics, _ := osCollector.CollectMetrics()

	return []*collectors.IdsecMetrics{
		metadataMetrics,
		envMetrics,
		osMetrics,
	}
}
