package collectors

import (
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

func TestNewIdsecOSMetricsCollector(t *testing.T) {
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

			collector := NewIdsecOSMetricsCollector()

			if collector == nil {
				t.Error("Expected non-nil collector")
			}

			if _, ok := collector.(*IdsecOSMetricsCollector); !ok && tt.expected {
				t.Error("Expected collector to be of type *IdsecOSMetricsCollector")
			}
		})
	}
}

func TestIdsecOSMetricsCollector_CollectMetrics(t *testing.T) {
	tests := []struct {
		name             string
		validateFunc     func(t *testing.T, metrics *IdsecMetrics)
		expectedMinCount int
	}{
		{
			name:             "success_collects_all_os_metrics",
			expectedMinCount: 5, // os_name, arch, cpu_count, go_version, timezone
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				if metrics.Collector != "os_metrics" {
					t.Errorf("Expected collector name 'os_metrics', got '%s'", metrics.Collector)
				}
				if metrics.ShortName != "om" {
					t.Errorf("Expected short name 'om', got '%s'", metrics.ShortName)
				}
			},
		},
		{
			name:             "success_includes_memory_total_metric",
			expectedMinCount: 5,
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				memMetric := findMetricByName(metrics.Metrics, "memory_total")
				if memMetric == nil {
					t.Error("Expected to find 'memory_total' metric")
				} else {
					if memMetric.ShortName != "mem" {
						t.Errorf("Expected memory_total short name 'mem', got '%s'", memMetric.ShortName)
					}
					// Memory value could be uint64 or "unknown"
					if memMetric.Value == nil {
						t.Error("Expected memory_total to have non-nil value")
					}
				}
			},
		},
		{
			name:             "success_includes_disk_total_metric",
			expectedMinCount: 5,
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				diskMetric := findMetricByName(metrics.Metrics, "disk_total")
				if diskMetric == nil {
					t.Error("Expected to find 'disk_total' metric")
				} else {
					if diskMetric.ShortName != "disk" {
						t.Errorf("Expected disk_total short name 'disk', got '%s'", diskMetric.ShortName)
					}
					// Disk value could be uint64 or "unknown"
					if diskMetric.Value == nil {
						t.Error("Expected disk_total to have non-nil value")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecOSMetricsCollector{}
			metrics, err := collector.CollectMetrics()

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if metrics == nil {
				t.Error("Expected non-nil metrics")
				return
			}

			if len(metrics.Metrics) < tt.expectedMinCount {
				t.Errorf("Expected at least %d metrics, got %d", tt.expectedMinCount, len(metrics.Metrics))
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, metrics)
			}
		})
	}
}

func TestIdsecOSMetricsCollector_CollectMetrics_AllMetricsPresent(t *testing.T) {
	tests := []struct {
		name               string
		expectedMetricName string
		expectedShortName  string
		validateValue      func(t *testing.T, value interface{})
	}{
		{
			name:               "success_os_name_metric_present",
			expectedMetricName: "os_name",
			expectedShortName:  "os",
			validateValue: func(t *testing.T, value interface{}) {
				osName, ok := value.(string)
				if !ok {
					t.Error("Expected os_name to be string")
					return
				}
				if osName != runtime.GOOS {
					t.Errorf("Expected os_name to be '%s', got '%s'", runtime.GOOS, osName)
				}
			},
		},
		{
			name:               "success_architecture_metric_present",
			expectedMetricName: "architecture",
			expectedShortName:  "arch",
			validateValue: func(t *testing.T, value interface{}) {
				arch, ok := value.(string)
				if !ok {
					t.Error("Expected architecture to be string")
					return
				}
				if arch != runtime.GOARCH {
					t.Errorf("Expected architecture to be '%s', got '%s'", runtime.GOARCH, arch)
				}
			},
		},
		{
			name:               "success_cpu_count_metric_present",
			expectedMetricName: "cpu_count",
			expectedShortName:  "cpu",
			validateValue: func(t *testing.T, value interface{}) {
				cpuCount, ok := value.(int)
				if !ok {
					t.Error("Expected cpu_count to be int")
					return
				}
				if cpuCount != runtime.NumCPU() {
					t.Errorf("Expected cpu_count to be %d, got %d", runtime.NumCPU(), cpuCount)
				}
			},
		},
		{
			name:               "success_go_version_metric_present",
			expectedMetricName: "go_version",
			expectedShortName:  "go_ver",
			validateValue: func(t *testing.T, value interface{}) {
				goVersion, ok := value.(string)
				if !ok {
					t.Error("Expected go_version to be string")
					return
				}
				if goVersion != runtime.Version() {
					t.Errorf("Expected go_version to be '%s', got '%s'", runtime.Version(), goVersion)
				}
			},
		},
		{
			name:               "success_timezone_metric_present",
			expectedMetricName: "timezone",
			expectedShortName:  "tz",
			validateValue: func(t *testing.T, value interface{}) {
				timezone, ok := value.(string)
				if !ok {
					t.Error("Expected timezone to be string")
					return
				}
				expectedTZ, _ := time.Now().Zone()
				if timezone != expectedTZ {
					t.Errorf("Expected timezone to be '%s', got '%s'", expectedTZ, timezone)
				}
			},
		},
		{
			name:               "success_memory_total_metric_present",
			expectedMetricName: "memory_total",
			expectedShortName:  "mem",
			validateValue: func(t *testing.T, value interface{}) {
				// Memory value can be uint64 or "unknown"
				switch v := value.(type) {
				case uint64:
					// Valid memory value
					if v == 0 {
						t.Error("Expected memory_total to be greater than 0")
					}
				case string:
					if v != "unknown" {
						t.Errorf("Expected memory_total string to be 'unknown', got '%s'", v)
					}
				default:
					t.Errorf("Expected memory_total to be uint64 or string, got %T", value)
				}
			},
		},
		{
			name:               "success_disk_total_metric_present",
			expectedMetricName: "disk_total",
			expectedShortName:  "disk",
			validateValue: func(t *testing.T, value interface{}) {
				// Disk value can be uint64 or "unknown"
				switch v := value.(type) {
				case uint64:
					// Valid disk value
					if v == 0 {
						t.Error("Expected disk_total to be greater than 0")
					}
				case string:
					if v != "unknown" {
						t.Errorf("Expected disk_total string to be 'unknown', got '%s'", v)
					}
				default:
					t.Errorf("Expected disk_total to be uint64 or string, got %T", value)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecOSMetricsCollector{}
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

			if tt.validateValue != nil {
				tt.validateValue(t, metric.Value)
			}
		})
	}
}

func TestIdsecOSMetricsCollector_IsDynamicMetrics(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "success_returns_false",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecOSMetricsCollector{}
			result := collector.IsDynamicMetrics()

			if result != tt.expected {
				t.Errorf("Expected IsDynamicMetrics() to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIdsecOSMetricsCollector_CollectorName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{
			name:     "success_returns_collector_name",
			expected: IdsecOSMetricsCollectorName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecOSMetricsCollector{}
			result := collector.CollectorName()

			if result != tt.expected {
				t.Errorf("Expected CollectorName() to return '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestIdsecOSMetricsCollector_MetricStructure(t *testing.T) {
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
					if metric.Value == nil {
						t.Errorf("Expected metric %s to have non-nil Value", metric.Name)
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

			collector := &IdsecOSMetricsCollector{}
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

func TestIdsecOSMetricsCollector_ConsistentMetricCount(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, firstCount, secondCount int)
	}{
		{
			name: "success_multiple_collections_same_metric_count",
			validateFunc: func(t *testing.T, firstCount, secondCount int) {
				if firstCount != secondCount {
					t.Errorf("Expected same metric count across collections, got %d and %d", firstCount, secondCount)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecOSMetricsCollector{}

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
				tt.validateFunc(t, len(metrics1.Metrics), len(metrics2.Metrics))
			}
		})
	}
}

func TestIdsecOSMetricsCollector_SystemMetricsValues(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, metrics *IdsecMetrics)
	}{
		{
			name: "success_memory_metric_has_valid_value",
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				memMetric := findMetricByName(metrics.Metrics, "memory_total")
				if memMetric == nil {
					t.Error("Expected to find memory_total metric")
					return
				}

				// Check against actual system memory
				vmStat, err := mem.VirtualMemory()
				if err == nil {
					if memValue, ok := memMetric.Value.(uint64); ok {
						if memValue != vmStat.Total {
							t.Errorf("Expected memory_total to match system memory %d, got %d", vmStat.Total, memValue)
						}
					}
				} else {
					if memMetric.Value != "unknown" {
						t.Error("Expected memory_total to be 'unknown' when gopsutil fails")
					}
				}
			},
		},
		{
			name: "success_disk_metric_has_valid_value",
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				diskMetric := findMetricByName(metrics.Metrics, "disk_total")
				if diskMetric == nil {
					t.Error("Expected to find disk_total metric")
					return
				}

				// Check against actual system disk
				diskStat, err := disk.Usage("/")
				if err == nil {
					if diskValue, ok := diskMetric.Value.(uint64); ok {
						if diskValue != diskStat.Total {
							t.Errorf("Expected disk_total to match system disk %d, got %d", diskStat.Total, diskValue)
						}
					}
				} else {
					if diskMetric.Value != "unknown" {
						t.Error("Expected disk_total to be 'unknown' when gopsutil fails")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecOSMetricsCollector{}
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

func TestIdsecOSMetricsCollector_MetricTypes(t *testing.T) {
	tests := []struct {
		name          string
		metricName    string
		expectedTypes []string // Can be multiple types
	}{
		{
			name:          "success_os_name_is_string",
			metricName:    "os_name",
			expectedTypes: []string{"string"},
		},
		{
			name:          "success_architecture_is_string",
			metricName:    "architecture",
			expectedTypes: []string{"string"},
		},
		{
			name:          "success_cpu_count_is_int",
			metricName:    "cpu_count",
			expectedTypes: []string{"int"},
		},
		{
			name:          "success_go_version_is_string",
			metricName:    "go_version",
			expectedTypes: []string{"string"},
		},
		{
			name:          "success_timezone_is_string",
			metricName:    "timezone",
			expectedTypes: []string{"string"},
		},
		{
			name:          "success_memory_total_is_uint64_or_string",
			metricName:    "memory_total",
			expectedTypes: []string{"uint64", "string"},
		},
		{
			name:          "success_disk_total_is_uint64_or_string",
			metricName:    "disk_total",
			expectedTypes: []string{"uint64", "string"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecOSMetricsCollector{}
			metrics, err := collector.CollectMetrics()

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			metric := findMetricByName(metrics.Metrics, tt.metricName)
			if metric == nil {
				t.Errorf("Expected to find '%s' metric", tt.metricName)
				return
			}

			actualType := reflect.TypeOf(metric.Value).String()
			validType := false
			for _, expectedType := range tt.expectedTypes {
				if actualType == expectedType {
					validType = true
					break
				}
			}

			if !validType {
				t.Errorf("Expected %s to be one of %v, got %s", tt.metricName, tt.expectedTypes, actualType)
			}
		})
	}
}
