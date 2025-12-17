package collectors

import (
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/detectors"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/detectors/cloud"
)

const (
	// IdsecEnvironmentMetricsCollectorName is the name of the environment metrics collector
	IdsecEnvironmentMetricsCollectorName = "environment_metrics"
)

// IdsecEnvironmentMetricsCollector collects environment metrics about the Idsec tool in use.
//
// CollectMetrics collects environment details about the Idsec tool (environment type).
//
// Returns IdsecMetrics containing the collected environment metric.
//
// Example:
//
//		collector := &IdsecEnvironmentMetricsCollector{}
//		metrics, err := collector.CollectMetrics()
//		if err != nil {
//		    // handle error
//	}
type IdsecEnvironmentMetricsCollector struct {
	cloudDetector        detectors.IdsecEnvDetector
	detectedCloudContext *detectors.IdsecEnvContext
}

// NewIdsecEnvironmentMetricsCollector creates a new instance of IdsecEnvironmentMetricsCollector.
//
// Returns a pointer to the newly created IdsecEnvironmentMetricsCollector.
func NewIdsecEnvironmentMetricsCollector() IdsecMetricsCollector {
	return &IdsecEnvironmentMetricsCollector{
		cloudDetector: cloud.NewIdsecCloudEnvDetector(),
	}
}

// CollectMetrics collects and returns Idsec environment metrics.
//
// Returns IdsecMetrics with a single metric indicating the environment type.
func (c *IdsecEnvironmentMetricsCollector) CollectMetrics() (*IdsecMetrics, error) {
	metrics := &IdsecMetrics{
		Collector: IdsecEnvironmentMetricsCollectorName,
		ShortName: "em",
		Metrics:   []IdsecMetric{},
	}

	proxyVars := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"}
	hasProxy := false
	for _, proxyVar := range proxyVars {
		if os.Getenv(proxyVar) != "" {
			hasProxy = true
			break
		}
	}
	metrics.Metrics = append(metrics.Metrics,
		IdsecMetric{
			Name:      "proxy_configured",
			ShortName: "pc",
			Value:     hasProxy,
		},
	)

	var envContext *detectors.IdsecEnvContext
	if c.detectedCloudContext != nil {
		envContext = c.detectedCloudContext
	} else {
		envContext, _ = c.cloudDetector.Detect()
		c.detectedCloudContext = envContext
	}

	// We do not fill account / instance as they are sensitive information
	metrics.Metrics = append(metrics.Metrics,
		IdsecMetric{
			Name:      "provider",
			ShortName: "prv",
			Value:     envContext.Provider,
		},
		IdsecMetric{
			Name:      "environment",
			ShortName: "env",
			Value:     envContext.Environment,
		},
		IdsecMetric{
			Name:      "region",
			ShortName: "reg",
			Value:     envContext.Region,
		},
	)

	return metrics, nil
}

// IsDynamicMetrics indicates whether the collected metrics are dynamic.
//
// Returns false as environment metrics are static.
func (c *IdsecEnvironmentMetricsCollector) IsDynamicMetrics() bool {
	return false
}

// CollectorName returns the name of the collector
func (c *IdsecEnvironmentMetricsCollector) CollectorName() string {
	return IdsecEnvironmentMetricsCollectorName
}
