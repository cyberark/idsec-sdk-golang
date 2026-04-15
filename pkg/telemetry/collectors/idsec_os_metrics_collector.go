package collectors

import (
	"runtime"
	"time"
)

const (
	// IdsecOSMetricsCollectorName is the name of the OS metrics collector
	IdsecOSMetricsCollectorName = "os_metrics"
)

// IdsecOSMetricsCollector collects OS and system metrics using runtime.
//
// CollectMetrics collects OS details (name, arch, Go version, timezone).
//
// Returns IdsecMetrics containing all collected metrics.
//
// Example:
//
//	collector := &IdsecOSMetricsCollector{}
//	metrics, err := collector.CollectMetrics()
//	if err != nil {
//	    // handle error
//	}
type IdsecOSMetricsCollector struct{}

// NewIdsecOSMetricsCollector creates a new instance of IdsecOSMetricsCollector.
//
// Returns a pointer to the newly created IdsecOSMetricsCollector.
func NewIdsecOSMetricsCollector() IdsecMetricsCollector {
	return &IdsecOSMetricsCollector{}
}

// CollectMetrics collects and returns Idsec OS metrics.
//
// Returns IdsecMetrics with metrics slice containing OS details.
func (c *IdsecOSMetricsCollector) CollectMetrics() (*IdsecMetrics, error) {
	metrics := &IdsecMetrics{
		Collector: "os_metrics",
		ShortName: "om",
		Metrics:   []IdsecMetric{},
	}

	// Collect OS details
	osName := runtime.GOOS
	arch := runtime.GOARCH
	goVersion := runtime.Version()
	name, _ := time.Now().Zone()
	metrics.Metrics = append(metrics.Metrics,
		IdsecMetric{
			Name:      "os_name",
			ShortName: "os",
			Value:     osName,
		},
		IdsecMetric{
			Name:      "architecture",
			ShortName: "arch",
			Value:     arch,
		},
		IdsecMetric{
			Name:      "go_version",
			ShortName: "go_ver",
			Value:     goVersion,
		},
		IdsecMetric{
			Name:      "timezone",
			ShortName: "tz",
			Value:     name,
		},
	)

	return metrics, nil
}

// IsDynamicMetrics indicates whether the collected metrics are dynamic.
//
// Returns false as OS metrics are mostly static.
func (c *IdsecOSMetricsCollector) IsDynamicMetrics() bool {
	return false
}

// CollectorName returns the name of the collector.
func (c *IdsecOSMetricsCollector) CollectorName() string {
	return IdsecOSMetricsCollectorName
}
