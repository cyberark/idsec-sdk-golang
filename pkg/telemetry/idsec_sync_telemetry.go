package telemetry

import (
	"sync"

	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/encoders"
)

// IdsecSyncTelemetry represents telemetry data for IDSEC SDK applications.
type IdsecSyncTelemetry struct {
	Collectors               []collectors.IdsecMetricsCollector
	Encoder                  encoders.IdsecMetricsEncoder
	lastCollectedMetrics     map[string]*collectors.IdsecMetrics
	lastCollectedMetricsLock sync.Mutex
	lastCollectedEncoded     []byte
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

// CollectAndEncodeMetrics collects metrics from all collectors and encodes them using the specified encoder.
func (a *IdsecSyncTelemetry) CollectAndEncodeMetrics() ([]byte, error) {
	// If all the collectors are static, no need to collect anything
	// Reuse existing collected metrics
	if a.lastCollectedEncoded != nil {
		isStaticCollection := true
		for _, collector := range a.Collectors {
			if collector.IsDynamicMetrics() {
				isStaticCollection = false
				break
			}
		}
		if isStaticCollection {
			return a.lastCollectedEncoded, nil
		}
	}
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
		metrics, err := collector.CollectMetrics()
		if err != nil {
			return nil, err
		}
		a.lastCollectedMetrics[collector.CollectorName()] = metrics
		allMetrics = append(allMetrics, metrics)
	}
	// Encode all collected metrics
	encodedMetrics, err := a.Encoder.EncodeMetrics(allMetrics)
	if err != nil {
		return nil, err
	}
	a.lastCollectedEncoded = encodedMetrics
	return encodedMetrics, nil
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
