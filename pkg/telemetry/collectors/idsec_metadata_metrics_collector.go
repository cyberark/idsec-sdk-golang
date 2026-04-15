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
//
// extraContextField stores both the full name and value for a tool context metric.
type extraContextField struct {
	name  string
	value string
}

type IdsecMetadataMetricsCollector struct {
	route                     string
	service                   string
	class                     string
	operation                 string
	extraContextFields        map[string]extraContextField // Dynamic tool-specific context fields (shortName -> {name, value})
	changedFromLastCollection bool
}

// NewIdsecMetadataMetricsCollector creates a new instance of IdsecMetadataMetricsCollector.
//
// Returns a pointer to the newly created IdsecMetadataMetricsCollector.
func NewIdsecMetadataMetricsCollector() IdsecMetricsCollector {
	return &IdsecMetadataMetricsCollector{
		extraContextFields:        make(map[string]extraContextField),
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

	// Add dynamic tool context fields
	for shortName, field := range c.extraContextFields {
		metrics.Metrics = append(metrics.Metrics, IdsecMetric{
			Name:      field.name,
			ShortName: shortName,
			Value:     field.value,
		})
	}

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

// AddExtraContextField adds a tool-specific context field to the metadata metrics.
//
// AddExtraContextField allows tools (Terraform, CLI, SDK, etc.) to add arbitrary
// context fields to the telemetry metadata. Tools provide both a full descriptive
// name and a short name for efficient transmission.
//
// Parameters:
//   - name: The full descriptive name for the field (e.g., "terraform_resource", "cli_command")
//   - shortName: The short identifier for the field (e.g., "tfr", "clic")
//   - value: The value to associate with this field
//
// Example:
//
//	collector.AddExtraContextField("terraform_resource", "tfr", "idsec_user")
//	collector.AddExtraContextField("cli_command", "clic", "login")
func (c *IdsecMetadataMetricsCollector) AddExtraContextField(name, shortName, value string) {
	if c.extraContextFields == nil {
		c.extraContextFields = make(map[string]extraContextField)
	}
	c.extraContextFields[shortName] = extraContextField{
		name:  name,
		value: value,
	}
	c.changedFromLastCollection = true
}

// GetExtraContextField retrieves a tool-specific context field value.
//
// Parameters:
//   - shortName: The short identifier for the field to retrieve
//
// Returns the field value and a boolean indicating if the field exists.
//
// Example:
//
//	value, exists := collector.GetExtraContextField("tfr")
func (c *IdsecMetadataMetricsCollector) GetExtraContextField(shortName string) (string, bool) {
	field, exists := c.extraContextFields[shortName]
	return field.value, exists
}

// ClearExtraContext clears all tool-specific context fields.
//
// ClearExtraContext removes all dynamically added tool context fields,
// typically called after a request completes to prevent context from
// leaking into subsequent requests.
//
// Example:
//
//	defer collector.ClearExtraContext()
func (c *IdsecMetadataMetricsCollector) ClearExtraContext() {
	c.extraContextFields = make(map[string]extraContextField)
	c.changedFromLastCollection = true
}
