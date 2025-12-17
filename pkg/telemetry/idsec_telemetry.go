package telemetry

import "github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"

// IdsecTelemetry represents telemetry data for IDSEC SDK applications.
type IdsecTelemetry interface {
	// CollectAndEncodeMetrics collects metrics from all collectors and encodes them.
	CollectAndEncodeMetrics() ([]byte, error)
	// CollectorByName returns the IdsecMetricsCollector with the specified name, or nil if not found.
	CollectorByName(name string) collectors.IdsecMetricsCollector
}
