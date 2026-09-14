package collectors

import (
	"testing"
)

func TestNewIdsecMetadataMetricsCollector(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "success_creates_collector_instance",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := NewIdsecMetadataMetricsCollector()

			if collector == nil {
				t.Error("Expected non-nil collector")
			}

			if _, ok := collector.(*IdsecMetadataMetricsCollector); !ok && tt.expected {
				t.Error("Expected collector to be of type *IdsecMetadataMetricsCollector")
			}

			// Verify initial state
			metadataCollector := collector.(*IdsecMetadataMetricsCollector)
			if len(metadataCollector.extraContextFields) != 0 {
				t.Errorf("Expected no tool context fields, got %d", len(metadataCollector.extraContextFields))
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_CollectMetrics(t *testing.T) {
	tests := []struct {
		name            string
		request         IdsecRequestMetadata
		expectedMetrics int
		validateFunc    func(t *testing.T, metrics *IdsecMetrics)
	}{
		{
			name:            "success_collects_all_metadata_metrics",
			expectedMetrics: 13, // Base metrics without tool context fields
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				if metrics.Collector != IdsecMetadataMetricsCollectorName {
					t.Errorf("Expected collector name '%s', got '%s'", IdsecMetadataMetricsCollectorName, metrics.Collector)
				}
				if metrics.ShortName != "mm" {
					t.Errorf("Expected short name 'mm', got '%s'", metrics.ShortName)
				}
			},
		},
		{
			name: "success_reports_the_given_request",
			request: IdsecRequestMetadata{
				Route:     "test-route",
				Service:   "test-service",
				Class:     "test-class",
				Operation: "test-operation",
			},
			expectedMetrics: 13, // Base metrics without tool context fields
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				for name, expected := range map[string]string{
					"route":     "test-route",
					"service":   "test-service",
					"class":     "test-class",
					"operation": "test-operation",
				} {
					metric := findMetricByName(metrics.Metrics, name)
					if metric == nil {
						t.Errorf("Expected to find '%s' metric", name)
						continue
					}
					if metric.Value != expected {
						t.Errorf("Expected %s value '%s', got '%v'", name, expected, metric.Value)
					}
				}
			},
		},
		{
			name:            "success_reports_an_empty_request",
			request:         IdsecRequestMetadata{},
			expectedMetrics: 13, // Base metrics without tool context fields
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				serviceMetric := findMetricByName(metrics.Metrics, "service")
				if serviceMetric == nil {
					t.Error("Expected to find 'service' metric")
				} else if serviceMetric.Value != "" {
					t.Errorf("Expected empty service value, got '%v'", serviceMetric.Value)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{}
			metrics, err := collector.CollectMetricsForRequest(tt.request)

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if metrics == nil {
				t.Error("Expected non-nil metrics")
				return
			}

			if len(metrics.Metrics) != tt.expectedMetrics {
				t.Errorf("Expected %d metrics, got %d", tt.expectedMetrics, len(metrics.Metrics))
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, metrics)
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_CollectMetrics_AllMetricsPresent(t *testing.T) {
	tests := []struct {
		name               string
		expectedMetricName string
		expectedShortName  string
	}{
		{
			name:               "success_idsec_tool_metric_present",
			expectedMetricName: "idsec_tool",
			expectedShortName:  "at",
		},
		{
			name:               "success_idsec_version_metric_present",
			expectedMetricName: "idsec_version",
			expectedShortName:  "av",
		},
		{
			name:               "success_idsec_build_number_metric_present",
			expectedMetricName: "idsec_build_number",
			expectedShortName:  "abn",
		},
		{
			name:               "success_idsec_build_date_metric_present",
			expectedMetricName: "idsec_build_date",
			expectedShortName:  "abd",
		},
		{
			name:               "success_idsec_git_commit_metric_present",
			expectedMetricName: "idsec_git_commit",
			expectedShortName:  "agc",
		},
		{
			name:               "success_idsec_git_branch_metric_present",
			expectedMetricName: "idsec_git_branch",
			expectedShortName:  "agb",
		},
		{
			name:               "success_correlation_id_metric_present",
			expectedMetricName: "correlation_id",
			expectedShortName:  "cid",
		},
		{
			name:               "success_service_metric_present",
			expectedMetricName: "service",
			expectedShortName:  "svc",
		},
		{
			name:               "success_class_metric_present",
			expectedMetricName: "class",
			expectedShortName:  "cls",
		},
		{
			name:               "success_operation_metric_present",
			expectedMetricName: "operation",
			expectedShortName:  "op",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{}
			metrics, err := collector.CollectMetrics()

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			metric := findMetricByName(metrics.Metrics, tt.expectedMetricName)
			if metric == nil {
				t.Errorf("Expected to find '%s' metric", tt.expectedMetricName)
				return
			}

			if metric.ShortName != tt.expectedShortName {
				t.Errorf("Expected short name '%s', got '%s'", tt.expectedShortName, metric.ShortName)
			}

			if metric.Name != tt.expectedMetricName {
				t.Errorf("Expected metric name '%s', got '%s'", tt.expectedMetricName, metric.Name)
			}
		})
	}
}

// These metrics describe the request being sent, so the collector must always
// report itself dynamic. Reporting otherwise would let one request's header be
// cached and sent for another.
func TestIdsecMetadataMetricsCollector_IsDynamicMetrics(t *testing.T) {
	t.Parallel()

	collector := &IdsecMetadataMetricsCollector{}
	if !collector.IsDynamicMetrics() {
		t.Error("Expected IsDynamicMetrics() to return true")
	}

	// Collecting must not make it cacheable either.
	if _, err := collector.CollectMetricsForRequest(IdsecRequestMetadata{Route: "/a"}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !collector.IsDynamicMetrics() {
		t.Error("Expected IsDynamicMetrics() to still return true after collection")
	}
}

func TestIdsecMetadataMetricsCollector_CollectorName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{
			name:     "success_returns_collector_name",
			expected: IdsecMetadataMetricsCollectorName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{}
			result := collector.CollectorName()

			if result != tt.expected {
				t.Errorf("Expected CollectorName() to return '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_MetricStructure(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, metrics *IdsecMetrics)
	}{
		{
			name: "success_all_metrics_have_required_fields",
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				for _, metric := range metrics.Metrics {
					if metric.Name == "" {
						t.Error("Expected all metrics to have non-empty Name")
					}
					if metric.ShortName == "" {
						t.Error("Expected all metrics to have non-empty ShortName")
					}
				}
			},
		},
		{
			name: "success_metric_names_are_unique",
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				seen := make(map[string]bool)
				for _, metric := range metrics.Metrics {
					if seen[metric.Name] {
						t.Errorf("Duplicate metric name found: %s", metric.Name)
					}
					seen[metric.Name] = true
				}
			},
		},
		{
			name: "success_metric_short_names_are_unique",
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				seen := make(map[string]bool)
				for _, metric := range metrics.Metrics {
					if seen[metric.ShortName] {
						t.Errorf("Duplicate metric short name found: %s", metric.ShortName)
					}
					seen[metric.ShortName] = true
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{}
			metrics, err := collector.CollectMetrics()

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, metrics)
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_Integration(t *testing.T) {
	tests := []struct {
		name         string
		setupFunc    func() *IdsecMetadataMetricsCollector
		validateFunc func(t *testing.T, collector *IdsecMetadataMetricsCollector, metrics1, metrics2 *IdsecMetrics)
	}{
		{
			name: "success_reports_each_request_on_its_own_terms",
			setupFunc: func() *IdsecMetadataMetricsCollector {
				return &IdsecMetadataMetricsCollector{}
			},
			validateFunc: func(t *testing.T, collector *IdsecMetadataMetricsCollector, metrics1, metrics2 *IdsecMetrics) {
				// Each collection must report the request it was given rather
				// than the last one the collector happened to see.
				first, err := collector.CollectMetricsForRequest(IdsecRequestMetadata{Route: "/first"})
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				second, err := collector.CollectMetricsForRequest(IdsecRequestMetadata{Route: "/second"})
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if route := findMetricByName(first.Metrics, "route"); route == nil || route.Value != "/first" {
					t.Errorf("First request reported route %v, want /first", route)
				}
				if route := findMetricByName(second.Metrics, "route"); route == nil || route.Value != "/second" {
					t.Errorf("Second request reported route %v, want /second", route)
				}
			},
		},
		{
			name: "success_metrics_consistent_across_collections",
			setupFunc: func() *IdsecMetadataMetricsCollector {
				return &IdsecMetadataMetricsCollector{}
			},
			validateFunc: func(t *testing.T, collector *IdsecMetadataMetricsCollector, metrics1, metrics2 *IdsecMetrics) {
				if len(metrics1.Metrics) != len(metrics2.Metrics) {
					t.Errorf("Expected same number of metrics, got %d and %d", len(metrics1.Metrics), len(metrics2.Metrics))
				}

				// Verify metric names are the same
				names1 := make(map[string]bool)
				for _, m := range metrics1.Metrics {
					names1[m.Name] = true
				}

				for _, m := range metrics2.Metrics {
					if !names1[m.Name] {
						t.Errorf("Metric %s present in second collection but not first", m.Name)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := tt.setupFunc()

			metrics1, err1 := collector.CollectMetrics()
			if err1 != nil {
				t.Errorf("Expected no error on first collection, got %v", err1)
				return
			}

			metrics2, err2 := collector.CollectMetrics()
			if err2 != nil {
				t.Errorf("Expected no error on second collection, got %v", err2)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, collector, metrics1, metrics2)
			}
		})
	}
}
