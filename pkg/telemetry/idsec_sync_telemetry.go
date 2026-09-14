package telemetry

import (
	"sync"

	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/encoders"
)

// IdsecSyncTelemetry represents telemetry data for IDSEC SDK applications.
type IdsecSyncTelemetry struct {
	Collectors []collectors.IdsecMetricsCollector
	Encoder    encoders.IdsecMetricsEncoder
	// lastCollectedMetricsLock guards lastCollectedMetrics, which caches the
	// collectors that report themselves static so that probing the OS and the
	// environment is not repeated for every request.
	//
	// The encoded header is deliberately not cached alongside them: it
	// describes one request, so a cached one would be sent for another.
	lastCollectedMetricsLock sync.Mutex
	lastCollectedMetrics     map[string]*collectors.IdsecMetrics
}

// NewIdsecSyncTelemetry creates a new instance of IdsecTelemetry with the specified collectors and encoder.
func NewIdsecSyncTelemetry(metricsCollectors []collectors.IdsecMetricsCollector, encoder encoders.IdsecMetricsEncoder) IdsecTelemetry {
	return &IdsecSyncTelemetry{
		Collectors:           metricsCollectors,
		Encoder:              encoder,
		lastCollectedMetrics: make(map[string]*collectors.IdsecMetrics),
	}
}

// NewDefaultIdsecSyncTelemetry creates a new IdsecTelemetry instance with default collectors and encoder.
func NewDefaultIdsecSyncTelemetry() IdsecTelemetry {
	return NewIdsecSyncTelemetry(
		[]collectors.IdsecMetricsCollector{
			collectors.NewIdsecEnvironmentMetricsCollector(),
			collectors.NewIdsecMetadataMetricsCollector(),
			collectors.NewIdsecOSMetricsCollector(),
		},
		encoders.NewIdsecTelemetryHeaderMetricsEncoder(),
	)
}

// NewLimitedIdsecSyncTelemetry creates a new IdsecTelemetry instance with limited collectors and encoder.
func NewLimitedIdsecSyncTelemetry() IdsecTelemetry {
	return NewIdsecSyncTelemetry(
		[]collectors.IdsecMetricsCollector{
			collectors.NewIdsecMetadataMetricsCollector(),
		},
		encoders.NewIdsecTelemetryHeaderMetricsEncoder(),
	)
}

// CollectAndEncodeMetrics collects metrics from all collectors and encodes them
// into a header describing the given request.
//
// A collector that knows how to describe a request is given it; the rest are
// collected as usual, and those reporting themselves static are collected only
// once. The resulting header is built fresh every time, because the request
// part of it differs for every request.
//
// Parameters:
//   - request: The request the header is being built for
//
// Returns the encoded header, or an error if a collector or the encoder failed.
func (a *IdsecSyncTelemetry) CollectAndEncodeMetrics(request collectors.IdsecRequestMetadata) ([]byte, error) {
	// Collect metrics from each collector
	// If the collector is static and we have already collected metrics from it, reuse them
	// Note that we need to lock access to lastCollectedMetrics map to avoid multiple goroutines collecting metrics at the same time
	var allMetrics []*collectors.IdsecMetrics
	a.lastCollectedMetricsLock.Lock()
	defer a.lastCollectedMetricsLock.Unlock()
	for _, collector := range a.Collectors {
		if !collector.IsDynamicMetrics() {
			_, ok := a.lastCollectedMetrics[collector.CollectorName()]
			if ok {
				allMetrics = append(allMetrics, a.lastCollectedMetrics[collector.CollectorName()])
				continue
			}
		}
		metrics, err := collectMetrics(collector, request)
		if err != nil {
			return nil, err
		}
		a.lastCollectedMetrics[collector.CollectorName()] = metrics
		allMetrics = append(allMetrics, metrics)
	}
	// Encode all collected metrics
	return a.Encoder.EncodeMetrics(allMetrics)
}

// requestMetricsCollector is a collector that describes a single request rather
// than the process it is running in.
type requestMetricsCollector interface {
	CollectMetricsForRequest(request collectors.IdsecRequestMetadata) (*collectors.IdsecMetrics, error)
}

// collectMetrics collects from a collector, passing it the request when it is
// able to describe one.
func collectMetrics(collector collectors.IdsecMetricsCollector, request collectors.IdsecRequestMetadata) (*collectors.IdsecMetrics, error) {
	if forRequest, ok := collector.(requestMetricsCollector); ok {
		return forRequest.CollectMetricsForRequest(request)
	}
	return collector.CollectMetrics()
}

// CollectorByName returns the IdsecMetricsCollector with the specified name, or nil if not found.
func (a *IdsecSyncTelemetry) CollectorByName(name string) collectors.IdsecMetricsCollector {
	for _, collector := range a.Collectors {
		if collector.CollectorName() == name {
			return collector
		}
	}
	return nil
}
