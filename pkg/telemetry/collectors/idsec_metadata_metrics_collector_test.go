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
			if metadataCollector.service != "" {
				t.Errorf("Expected empty service, got '%s'", metadataCollector.service)
			}
			if metadataCollector.class != "" {
				t.Errorf("Expected empty class, got '%s'", metadataCollector.class)
			}
			if metadataCollector.operation != "" {
				t.Errorf("Expected empty operation, got '%s'", metadataCollector.operation)
			}
			if !metadataCollector.changedFromLastCollection {
				t.Error("Expected changedFromLastCollection to be true initially")
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_CollectMetrics(t *testing.T) {
	tests := []struct {
		name            string
		setupCollector  func() *IdsecMetadataMetricsCollector
		expectedMetrics int
		validateFunc    func(t *testing.T, metrics *IdsecMetrics)
		expectedChanged bool
	}{
		{
			name: "success_collects_all_metadata_metrics",
			setupCollector: func() *IdsecMetadataMetricsCollector {
				return &IdsecMetadataMetricsCollector{
					changedFromLastCollection: true,
				}
			},
			expectedMetrics: 13,
			expectedChanged: false,
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
			name: "success_with_service_class_operation_set",
			setupCollector: func() *IdsecMetadataMetricsCollector {
				return &IdsecMetadataMetricsCollector{
					route:                     "test-route",
					service:                   "test-service",
					class:                     "test-class",
					operation:                 "test-operation",
					changedFromLastCollection: true,
				}
			},
			expectedMetrics: 13,
			expectedChanged: false,
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				serviceMetric := findMetricByName(metrics.Metrics, "service")
				if serviceMetric == nil {
					t.Error("Expected to find 'service' metric")
				} else if serviceMetric.Value != "test-service" {
					t.Errorf("Expected service value 'test-service', got '%v'", serviceMetric.Value)
				}

				classMetric := findMetricByName(metrics.Metrics, "class")
				if classMetric == nil {
					t.Error("Expected to find 'class' metric")
				} else if classMetric.Value != "test-class" {
					t.Errorf("Expected class value 'test-class', got '%v'", classMetric.Value)
				}

				operationMetric := findMetricByName(metrics.Metrics, "operation")
				if operationMetric == nil {
					t.Error("Expected to find 'operation' metric")
				} else if operationMetric.Value != "test-operation" {
					t.Errorf("Expected operation value 'test-operation', got '%v'", operationMetric.Value)
				}
			},
		},
		{
			name: "success_empty_service_class_operation",
			setupCollector: func() *IdsecMetadataMetricsCollector {
				return &IdsecMetadataMetricsCollector{
					route:                     "",
					service:                   "",
					class:                     "",
					operation:                 "",
					changedFromLastCollection: true,
				}
			},
			expectedMetrics: 13,
			expectedChanged: false,
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				serviceMetric := findMetricByName(metrics.Metrics, "service")
				if serviceMetric == nil {
					t.Error("Expected to find 'service' metric")
				} else if serviceMetric.Value != "" {
					t.Errorf("Expected empty service value, got '%v'", serviceMetric.Value)
				}
			},
		},
		{
			name: "success_resets_changed_flag_after_collection",
			setupCollector: func() *IdsecMetadataMetricsCollector {
				return &IdsecMetadataMetricsCollector{
					changedFromLastCollection: true,
				}
			},
			expectedMetrics: 13,
			expectedChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := tt.setupCollector()
			metrics, err := collector.CollectMetrics()

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

			if collector.changedFromLastCollection != tt.expectedChanged {
				t.Errorf("Expected changedFromLastCollection to be %v, got %v", tt.expectedChanged, collector.changedFromLastCollection)
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

func TestIdsecMetadataMetricsCollector_IsDynamicMetrics(t *testing.T) {
	tests := []struct {
		name                      string
		changedFromLastCollection bool
		expected                  bool
	}{
		{
			name:                      "success_returns_true_when_changed",
			changedFromLastCollection: true,
			expected:                  true,
		},
		{
			name:                      "success_returns_false_when_not_changed",
			changedFromLastCollection: false,
			expected:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				changedFromLastCollection: tt.changedFromLastCollection,
			}
			result := collector.IsDynamicMetrics()

			if result != tt.expected {
				t.Errorf("Expected IsDynamicMetrics() to return %v, got %v", tt.expected, result)
			}
		})
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

func TestIdsecMetadataMetricsCollector_SetService(t *testing.T) {
	tests := []struct {
		name            string
		initialService  string
		newService      string
		expectedService string
		expectedChanged bool
	}{
		{
			name:            "success_sets_service_and_marks_changed",
			initialService:  "",
			newService:      "new-service",
			expectedService: "new-service",
			expectedChanged: true,
		},
		{
			name:            "success_updates_existing_service",
			initialService:  "old-service",
			newService:      "new-service",
			expectedService: "new-service",
			expectedChanged: true,
		},
		{
			name:            "success_sets_empty_service",
			initialService:  "existing-service",
			newService:      "",
			expectedService: "",
			expectedChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				service:                   tt.initialService,
				changedFromLastCollection: false,
			}

			collector.SetService(tt.newService)

			if collector.service != tt.expectedService {
				t.Errorf("Expected service '%s', got '%s'", tt.expectedService, collector.service)
			}

			if collector.changedFromLastCollection != tt.expectedChanged {
				t.Errorf("Expected changedFromLastCollection to be %v, got %v", tt.expectedChanged, collector.changedFromLastCollection)
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_SetClass(t *testing.T) {
	tests := []struct {
		name            string
		initialClass    string
		newClass        string
		expectedClass   string
		expectedChanged bool
	}{
		{
			name:            "success_sets_class_and_marks_changed",
			initialClass:    "",
			newClass:        "new-class",
			expectedClass:   "new-class",
			expectedChanged: true,
		},
		{
			name:            "success_updates_existing_class",
			initialClass:    "old-class",
			newClass:        "new-class",
			expectedClass:   "new-class",
			expectedChanged: true,
		},
		{
			name:            "success_sets_empty_class",
			initialClass:    "existing-class",
			newClass:        "",
			expectedClass:   "",
			expectedChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				class:                     tt.initialClass,
				changedFromLastCollection: false,
			}

			collector.SetClass(tt.newClass)

			if collector.class != tt.expectedClass {
				t.Errorf("Expected class '%s', got '%s'", tt.expectedClass, collector.class)
			}

			if collector.changedFromLastCollection != tt.expectedChanged {
				t.Errorf("Expected changedFromLastCollection to be %v, got %v", tt.expectedChanged, collector.changedFromLastCollection)
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_SetOperation(t *testing.T) {
	tests := []struct {
		name              string
		initialOperation  string
		newOperation      string
		expectedOperation string
		expectedChanged   bool
	}{
		{
			name:              "success_sets_operation_and_marks_changed",
			initialOperation:  "",
			newOperation:      "new-operation",
			expectedOperation: "new-operation",
			expectedChanged:   true,
		},
		{
			name:              "success_updates_existing_operation",
			initialOperation:  "old-operation",
			newOperation:      "new-operation",
			expectedOperation: "new-operation",
			expectedChanged:   true,
		},
		{
			name:              "success_sets_empty_operation",
			initialOperation:  "existing-operation",
			newOperation:      "",
			expectedOperation: "",
			expectedChanged:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				operation:                 tt.initialOperation,
				changedFromLastCollection: false,
			}

			collector.SetOperation(tt.newOperation)

			if collector.operation != tt.expectedOperation {
				t.Errorf("Expected operation '%s', got '%s'", tt.expectedOperation, collector.operation)
			}

			if collector.changedFromLastCollection != tt.expectedChanged {
				t.Errorf("Expected changedFromLastCollection to be %v, got %v", tt.expectedChanged, collector.changedFromLastCollection)
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_Service(t *testing.T) {
	tests := []struct {
		name            string
		service         string
		expectedService string
	}{
		{
			name:            "success_returns_set_service",
			service:         "test-service",
			expectedService: "test-service",
		},
		{
			name:            "success_returns_empty_service",
			service:         "",
			expectedService: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				service: tt.service,
			}

			result := collector.Service()

			if result != tt.expectedService {
				t.Errorf("Expected Service() to return '%s', got '%s'", tt.expectedService, result)
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_Class(t *testing.T) {
	tests := []struct {
		name          string
		class         string
		expectedClass string
	}{
		{
			name:          "success_returns_set_class",
			class:         "test-class",
			expectedClass: "test-class",
		},
		{
			name:          "success_returns_empty_class",
			class:         "",
			expectedClass: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				class: tt.class,
			}

			result := collector.Class()

			if result != tt.expectedClass {
				t.Errorf("Expected Class() to return '%s', got '%s'", tt.expectedClass, result)
			}
		})
	}
}

func TestIdsecMetadataMetricsCollector_Operation(t *testing.T) {
	tests := []struct {
		name              string
		operation         string
		expectedOperation string
	}{
		{
			name:              "success_returns_set_operation",
			operation:         "test-operation",
			expectedOperation: "test-operation",
		},
		{
			name:              "success_returns_empty_operation",
			operation:         "",
			expectedOperation: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				operation: tt.operation,
			}

			result := collector.Operation()

			if result != tt.expectedOperation {
				t.Errorf("Expected Operation() to return '%s', got '%s'", tt.expectedOperation, result)
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

func TestIdsecMetadataMetricsCollector_ChangedFlagBehavior(t *testing.T) {
	tests := []struct {
		name         string
		setupFunc    func(collector *IdsecMetadataMetricsCollector)
		validateFunc func(t *testing.T, collector *IdsecMetadataMetricsCollector)
	}{
		{
			name: "success_collect_resets_changed_flag",
			setupFunc: func(collector *IdsecMetadataMetricsCollector) {
				collector.changedFromLastCollection = true
			},
			validateFunc: func(t *testing.T, collector *IdsecMetadataMetricsCollector) {
				_, err := collector.CollectMetrics()
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if collector.changedFromLastCollection {
					t.Error("Expected changedFromLastCollection to be false after CollectMetrics")
				}
			},
		},
		{
			name: "success_set_service_sets_changed_flag",
			setupFunc: func(collector *IdsecMetadataMetricsCollector) {
				collector.changedFromLastCollection = false
			},
			validateFunc: func(t *testing.T, collector *IdsecMetadataMetricsCollector) {
				collector.SetService("test")
				if !collector.changedFromLastCollection {
					t.Error("Expected changedFromLastCollection to be true after SetService")
				}
			},
		},
		{
			name: "success_set_class_sets_changed_flag",
			setupFunc: func(collector *IdsecMetadataMetricsCollector) {
				collector.changedFromLastCollection = false
			},
			validateFunc: func(t *testing.T, collector *IdsecMetadataMetricsCollector) {
				collector.SetClass("test")
				if !collector.changedFromLastCollection {
					t.Error("Expected changedFromLastCollection to be true after SetClass")
				}
			},
		},
		{
			name: "success_set_operation_sets_changed_flag",
			setupFunc: func(collector *IdsecMetadataMetricsCollector) {
				collector.changedFromLastCollection = false
			},
			validateFunc: func(t *testing.T, collector *IdsecMetadataMetricsCollector) {
				collector.SetOperation("test")
				if !collector.changedFromLastCollection {
					t.Error("Expected changedFromLastCollection to be true after SetOperation")
				}
			},
		},
		{
			name: "success_multiple_sets_keep_changed_flag_true",
			setupFunc: func(collector *IdsecMetadataMetricsCollector) {
				collector.changedFromLastCollection = false
			},
			validateFunc: func(t *testing.T, collector *IdsecMetadataMetricsCollector) {
				collector.SetService("test1")
				collector.SetClass("test2")
				collector.SetOperation("test3")
				if !collector.changedFromLastCollection {
					t.Error("Expected changedFromLastCollection to be true after multiple sets")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := &IdsecMetadataMetricsCollector{}

			if tt.setupFunc != nil {
				tt.setupFunc(collector)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, collector)
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
			name: "success_full_lifecycle_with_changes",
			setupFunc: func() *IdsecMetadataMetricsCollector {
				return &IdsecMetadataMetricsCollector{
					changedFromLastCollection: true,
				}
			},
			validateFunc: func(t *testing.T, collector *IdsecMetadataMetricsCollector, metrics1, metrics2 *IdsecMetrics) {
				// First collection
				if collector.IsDynamicMetrics() {
					t.Error("Expected IsDynamicMetrics to be false after first collection")
				}

				// Make changes
				collector.SetService("test-service")
				collector.SetClass("test-class")
				collector.SetOperation("test-operation")

				if !collector.IsDynamicMetrics() {
					t.Error("Expected IsDynamicMetrics to be true after changes")
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
