package collectors

import (
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

const (
	// IdsecOSMetricsCollectorName is the name of the OS metrics collector
	IdsecOSMetricsCollectorName = "os_metrics"
)

// IdsecOSMetricsCollector collects OS and system metrics using runtime and gopsutil.
//
// CollectMetrics collects OS details (name, arch, CPU count, Go version, hostname) and system metrics
// (memory usage, disk usage, CPU percent) using gopsutil.
//
// Returns IdsecMetrics containing all collected metrics, or error if any metric collection fails.
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

// CollectMetrics collects and returns Idsec OS and system metrics.
//
// Returns IdsecMetrics with metrics slice containing OS details and system metrics.
// If any gopsutil call fails, the corresponding metric value will be "unknown".
func (c *IdsecOSMetricsCollector) CollectMetrics() (*IdsecMetrics, error) {
	metrics := &IdsecMetrics{
		Collector: "os_metrics",
		ShortName: "om",
		Metrics:   []IdsecMetric{},
	}

	// Collect OS details
	osName := runtime.GOOS
	arch := runtime.GOARCH
	cpuCount := runtime.NumCPU()
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
			Name:      "cpu_count",
			ShortName: "cpu",
			Value:     cpuCount,
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

	// Collect memory usage
	vmStat, err := mem.VirtualMemory()
	if err == nil {
		metrics.Metrics = append(metrics.Metrics,
			IdsecMetric{
				Name:      "memory_total",
				ShortName: "mem",
				Value:     vmStat.Total,
			},
		)
	} else {
		metrics.Metrics = append(metrics.Metrics,
			IdsecMetric{
				Name:      "memory_total",
				ShortName: "mem",
				Value:     "unknown",
			},
		)
	}
	diskStat, err := disk.Usage("/")
	if err == nil {
		metrics.Metrics = append(metrics.Metrics,
			IdsecMetric{
				Name:      "disk_total",
				ShortName: "disk",
				Value:     diskStat.Total,
			},
		)
	} else {
		metrics.Metrics = append(metrics.Metrics,
			IdsecMetric{
				Name:      "disk_total",
				ShortName: "disk",
				Value:     "unknown",
			},
		)
	}

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
