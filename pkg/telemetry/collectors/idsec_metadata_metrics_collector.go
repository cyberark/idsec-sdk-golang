package collectors

import (
	"sync"
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

// IdsecRequestMetadata describes the single request a header is being built for.
//
// It is passed by value from the client rather than stored on the collector,
// because it differs for every request. A client sends requests from as many
// goroutines as its caller cares to use — the SDK's own fan-out helpers issue
// one per safe or per member — so a collector that held these fields would
// report whichever request happened to write them last.
type IdsecRequestMetadata struct {
	// Route is the path being requested.
	Route string
	// Service is the name of the service the client belongs to.
	Service string
	// Class is the type whose method is making the request.
	Class string
	// Operation is the method making the request.
	Operation string
}

type IdsecMetadataMetricsCollector struct {
	// extraContextFieldsLock guards extraContextFields, which outlives any one
	// request and is written by callers announcing what they are doing.
	extraContextFieldsLock sync.RWMutex
	extraContextFields     map[string]extraContextField // Dynamic tool-specific context fields (shortName -> {name, value})
}

// NewIdsecMetadataMetricsCollector creates a new instance of IdsecMetadataMetricsCollector.
//
// Returns a pointer to the newly created IdsecMetadataMetricsCollector.
func NewIdsecMetadataMetricsCollector() IdsecMetricsCollector {
	return &IdsecMetadataMetricsCollector{
		extraContextFields: make(map[string]extraContextField),
	}
}

// CollectMetrics collects and returns Idsec tool metadata metrics.
//
// The metrics describing a request are reported empty, because no request was
// given. Callers building a header for a request should use
// CollectMetricsForRequest instead.
//
// Returns IdsecMetrics with a single metric indicating the Idsec tool in use.
func (c *IdsecMetadataMetricsCollector) CollectMetrics() (*IdsecMetrics, error) {
	return c.CollectMetricsForRequest(IdsecRequestMetadata{})
}

// CollectMetricsForRequest collects Idsec tool metadata metrics describing a
// single request.
//
// Everything specific to the request is taken from request rather than from the
// collector, so that concurrent requests through one client cannot report each
// other's route or operation.
//
// Parameters:
//   - request: The request the metrics are being collected for
//
// Returns IdsecMetrics describing the tool, the request, and any tool context.
func (c *IdsecMetadataMetricsCollector) CollectMetricsForRequest(request IdsecRequestMetadata) (*IdsecMetrics, error) {
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
			Value:     request.Route,
		},
		IdsecMetric{
			Name:      "service",
			ShortName: "svc",
			Value:     request.Service,
		},
		IdsecMetric{
			Name:      "class",
			ShortName: "cls",
			Value:     request.Class,
		},
		IdsecMetric{
			Name:      "operation",
			ShortName: "op",
			Value:     request.Operation,
		},
		IdsecMetric{
			Name:      "deploy_env",
			ShortName: "de",
			Value:     common.GetDeployEnv(),
		},
	)

	// Add dynamic tool context fields
	c.extraContextFieldsLock.RLock()
	for shortName, field := range c.extraContextFields {
		metrics.Metrics = append(metrics.Metrics, IdsecMetric{
			Name:      field.name,
			ShortName: shortName,
			Value:     field.value,
		})
	}
	c.extraContextFieldsLock.RUnlock()

	return metrics, nil
}

// IsDynamicMetrics indicates whether the collected metrics are dynamic.
//
// Returns true, because these metrics describe the request being sent and so
// differ for every one of them. Reporting them as static would let a cached
// header from one request be reused for another.
func (c *IdsecMetadataMetricsCollector) IsDynamicMetrics() bool {
	return true
}

// CollectorName returns the name of the collector.
func (c *IdsecMetadataMetricsCollector) CollectorName() string {
	return IdsecMetadataMetricsCollectorName
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
	c.extraContextFieldsLock.Lock()
	defer c.extraContextFieldsLock.Unlock()
	if c.extraContextFields == nil {
		c.extraContextFields = make(map[string]extraContextField)
	}
	c.extraContextFields[shortName] = extraContextField{
		name:  name,
		value: value,
	}
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
	c.extraContextFieldsLock.RLock()
	defer c.extraContextFieldsLock.RUnlock()
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
	c.extraContextFieldsLock.Lock()
	defer c.extraContextFieldsLock.Unlock()
	c.extraContextFields = make(map[string]extraContextField)
}
