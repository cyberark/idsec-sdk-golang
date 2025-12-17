package collectors

import (
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

const (
	// IdsecMetadataMetricsCollectorName is the name of the metadata metrics collector
	IdsecMetadataMetricsCollectorName = "metadata_metrics"
)

// IdsecMetadataMetricsCollector collects metadata metrics about the Idsec tool in use.
//
// CollectMetrics collects metadata about the Idsec tool (SDK, CLI, or Terraform Provider).
//
// Returns IdsecMetrics containing the collected metadata metric.
//
// Example:
//
//	collector := &IdsecMetadataMetricsCollector{}
//	metrics, err := collector.CollectMetrics()
//	if err != nil {
//	    // handle error
//	}
type IdsecMetadataMetricsCollector struct {
	route                     string
	service                   string
	class                     string
	operation                 string
	changedFromLastCollection bool
}

// NewIdsecMetadataMetricsCollector creates a new instance of IdsecMetadataMetricsCollector.
//
// Returns a pointer to the newly created IdsecMetadataMetricsCollector.
func NewIdsecMetadataMetricsCollector() IdsecMetricsCollector {
	return &IdsecMetadataMetricsCollector{
		changedFromLastCollection: true,
	}
}

// CollectMetrics collects and returns Idsec tool metadata metrics.
//
// Returns IdsecMetrics with a single metric indicating the Idsec tool in use.
func (c *IdsecMetadataMetricsCollector) CollectMetrics() (*IdsecMetrics, error) {
	metrics := &IdsecMetrics{
		Collector: IdsecMetadataMetricsCollectorName,
		ShortName: "mm",
		Metrics:   []IdsecMetric{},
	}

	metrics.Metrics = append(metrics.Metrics,
		IdsecMetric{
			Name:      "idsec_tool",
			ShortName: "at",
			Value:     config.IdsecToolInUse(),
		},
		IdsecMetric{
			Name:      "idsec_version",
			ShortName: "av",
			Value:     config.IdsecVersion(),
		},
		IdsecMetric{
			Name:      "idsec_build_number",
			ShortName: "abn",
			Value:     config.IdsecBuildNumber(),
		},
		IdsecMetric{
			Name:      "idsec_build_date",
			ShortName: "abd",
			Value:     config.IdsecBuildDate(),
		},
		IdsecMetric{
			Name:      "idsec_git_commit",
			ShortName: "agc",
			Value:     config.IdsecGitCommit(),
		},
		IdsecMetric{
			Name:      "idsec_git_branch",
			ShortName: "agb",
			Value:     config.IdsecGitBranch(),
		},
		IdsecMetric{
			Name:      "correlation_id",
			ShortName: "cid",
			Value:     config.CorrelationID(),
		},
		IdsecMetric{
			Name:      "local_time",
			ShortName: "lt",
			Value:     time.Now().Format(time.RFC3339),
		},
		IdsecMetric{
			Name:      "route",
			ShortName: "rt",
			Value:     c.route,
		},
		IdsecMetric{
			Name:      "service",
			ShortName: "svc",
			Value:     c.service,
		},
		IdsecMetric{
			Name:      "class",
			ShortName: "cls",
			Value:     c.class,
		},
		IdsecMetric{
			Name:      "operation",
			ShortName: "op",
			Value:     c.operation,
		},
		IdsecMetric{
			Name:      "deploy_env",
			ShortName: "de",
			Value:     common.GetDeployEnv(),
		},
	)
	c.changedFromLastCollection = false
	return metrics, nil
}

// IsDynamicMetrics indicates whether the collected metrics are dynamic.
//
// Returns false as metadata metrics are static.
func (c *IdsecMetadataMetricsCollector) IsDynamicMetrics() bool {
	return c.changedFromLastCollection
}

// CollectorName returns the name of the collector.
func (c *IdsecMetadataMetricsCollector) CollectorName() string {
	return IdsecMetadataMetricsCollectorName
}

// SetRoute sets the route for the metadata metrics.
func (c *IdsecMetadataMetricsCollector) SetRoute(route string) {
	c.route = route
	c.changedFromLastCollection = true
}

// SetService sets the service name for the metadata metrics.
func (c *IdsecMetadataMetricsCollector) SetService(service string) {
	c.service = service
	c.changedFromLastCollection = true
}

// SetClass sets the class name for the metadata metrics.
func (c *IdsecMetadataMetricsCollector) SetClass(class string) {
	c.class = class
	c.changedFromLastCollection = true
}

// SetOperation sets the operation name for the metadata metrics.
func (c *IdsecMetadataMetricsCollector) SetOperation(operation string) {
	c.operation = operation
	c.changedFromLastCollection = true
}

// Route returns the route for the metadata metrics.
func (c *IdsecMetadataMetricsCollector) Route() string {
	return c.route
}

// Service returns the service name for the metadata metrics.
func (c *IdsecMetadataMetricsCollector) Service() string {
	return c.service
}

// Class returns the class name for the metadata metrics.
func (c *IdsecMetadataMetricsCollector) Class() string {
	return c.class
}

// Operation returns the operation name for the metadata metrics.
func (c *IdsecMetadataMetricsCollector) Operation() string {
	return c.operation
}
