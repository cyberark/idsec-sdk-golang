package collectors

// IdsecMetric represents a single metric with a name and value.
type IdsecMetric struct {
	Name      string
	ShortName string
	Value     interface{}
}

// IdsecMetrics represents a collection of metrics collected by a specific collector.
type IdsecMetrics struct {
	Collector string
	ShortName string
	Metrics   []IdsecMetric
}

// IdsecMetricsCollector is an interface that defines a method for collecting Idsec metrics.
type IdsecMetricsCollector interface {
	// CollectMetrics collects and returns Idsec metrics.
	CollectMetrics() (*IdsecMetrics, error)
	// IsDynamicMetrics returns whether this metric is changing or not
	IsDynamicMetrics() bool
	// CollectorName returns the name of the collector
	CollectorName() string
}
