package collectors

import (
	"os"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/detectors"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/detectors/cloud"
)

func findMetricByName(metrics []IdsecMetric, name string) *IdsecMetric {
	for i := range metrics {
		if metrics[i].Name == name {
			return &metrics[i]
		}
	}
	return nil
}

func TestNewIdsecEnvironmentMetricsCollector(t *testing.T) {
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

			collector := NewIdsecEnvironmentMetricsCollector()

			if collector == nil {
				t.Error("Expected non-nil collector")
			}

			if _, ok := collector.(*IdsecEnvironmentMetricsCollector); !ok && tt.expected {
				t.Error("Expected collector to be of type *IdsecEnvironmentMetricsCollector")
			}
		})
	}
}

func TestIdsecEnvironmentMetricsCollector_CollectMetrics(t *testing.T) {
	tests := []struct {
		name               string
		setupEnv           func()
		cleanupEnv         func()
		mockCloudDetector  func() *detectors.IdsecEnvDetector
		expectedProxyValue bool
		expectedProvider   string
		expectedEnv        string
		expectedRegion     string
		validateFunc       func(t *testing.T, metrics *IdsecMetrics)
	}{
		{
			name: "success_no_proxy_no_cloud",
			setupEnv: func() {
				os.Unsetenv("HTTP_PROXY")
				os.Unsetenv("HTTPS_PROXY")
				os.Unsetenv("http_proxy")
				os.Unsetenv("https_proxy")
			},
			cleanupEnv:         func() {},
			expectedProxyValue: false,
			expectedProvider:   "",
			expectedEnv:        "",
			expectedRegion:     "",
		},
		{
			name: "success_with_http_proxy_uppercase",
			setupEnv: func() {
				os.Setenv("HTTP_PROXY", "http://proxy.example.com:8080")
			},
			cleanupEnv: func() {
				os.Unsetenv("HTTP_PROXY")
			},
			expectedProxyValue: true,
			expectedProvider:   "",
			expectedEnv:        "",
			expectedRegion:     "",
		},
		{
			name: "success_with_https_proxy_uppercase",
			setupEnv: func() {
				os.Setenv("HTTPS_PROXY", "https://proxy.example.com:8443")
			},
			cleanupEnv: func() {
				os.Unsetenv("HTTPS_PROXY")
			},
			expectedProxyValue: true,
			expectedProvider:   "",
			expectedEnv:        "",
			expectedRegion:     "",
		},
		{
			name: "success_with_http_proxy_lowercase",
			setupEnv: func() {
				os.Setenv("http_proxy", "http://proxy.example.com:8080")
			},
			cleanupEnv: func() {
				os.Unsetenv("http_proxy")
			},
			expectedProxyValue: true,
			expectedProvider:   "",
			expectedEnv:        "",
			expectedRegion:     "",
		},
		{
			name: "success_with_https_proxy_lowercase",
			setupEnv: func() {
				os.Setenv("https_proxy", "https://proxy.example.com:8443")
			},
			cleanupEnv: func() {
				os.Unsetenv("https_proxy")
			},
			expectedProxyValue: true,
			expectedProvider:   "",
			expectedEnv:        "",
			expectedRegion:     "",
		},
		{
			name: "success_with_multiple_proxy_vars",
			setupEnv: func() {
				os.Setenv("HTTP_PROXY", "http://proxy1.example.com:8080")
				os.Setenv("https_proxy", "https://proxy2.example.com:8443")
			},
			cleanupEnv: func() {
				os.Unsetenv("HTTP_PROXY")
				os.Unsetenv("https_proxy")
			},
			expectedProxyValue: true,
			expectedProvider:   "",
			expectedEnv:        "",
			expectedRegion:     "",
		},
		{
			name: "success_with_cloud_context_aws",
			setupEnv: func() {
				os.Unsetenv("HTTP_PROXY")
				os.Unsetenv("HTTPS_PROXY")
				os.Unsetenv("http_proxy")
				os.Unsetenv("https_proxy")
			},
			cleanupEnv:         func() {},
			expectedProxyValue: false,
			expectedProvider:   "aws",
			expectedEnv:        "ec2",
			expectedRegion:     "us-east-1",
		},
		{
			name: "success_with_proxy_and_cloud_context",
			setupEnv: func() {
				os.Setenv("HTTP_PROXY", "http://proxy.example.com:8080")
			},
			cleanupEnv: func() {
				os.Unsetenv("HTTP_PROXY")
			},
			expectedProxyValue: true,
			expectedProvider:   "gcp",
			expectedEnv:        "gce",
			expectedRegion:     "us-central1",
		},
		{
			name: "success_empty_proxy_value_not_considered",
			setupEnv: func() {
				os.Setenv("HTTP_PROXY", "")
			},
			cleanupEnv: func() {
				os.Unsetenv("HTTP_PROXY")
			},
			expectedProxyValue: false,
			expectedProvider:   "",
			expectedEnv:        "",
			expectedRegion:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment
			if tt.setupEnv != nil {
				tt.setupEnv()
			}
			defer func() {
				if tt.cleanupEnv != nil {
					tt.cleanupEnv()
				}
			}()

			// Note: The actual cloud detector is called within CollectMetrics
			// This tests the current behavior of calling the real detector
			collector := &IdsecEnvironmentMetricsCollector{
				cloudDetector: cloud.NewIdsecCloudEnvDetector(),
			}
			metrics, err := collector.CollectMetrics()

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if metrics == nil {
				t.Error("Expected non-nil metrics")
				return
			}

			// Validate collector name
			if metrics.Collector != IdsecEnvironmentMetricsCollectorName {
				t.Errorf("Expected collector name '%s', got '%s'", IdsecEnvironmentMetricsCollectorName, metrics.Collector)
			}

			// Validate short name
			if metrics.ShortName != "em" {
				t.Errorf("Expected short name 'em', got '%s'", metrics.ShortName)
			}

			// Validate metrics count (should have 4 metrics: proxy, provider, environment, region)
			expectedMetricsCount := 4
			if len(metrics.Metrics) != expectedMetricsCount {
				t.Errorf("Expected %d metrics, got %d", expectedMetricsCount, len(metrics.Metrics))
			}

			// Validate proxy_configured metric
			proxyMetric := findMetricByName(metrics.Metrics, "proxy_configured")
			if proxyMetric == nil {
				t.Error("Expected to find 'proxy_configured' metric")
			} else {
				if proxyMetric.ShortName != "pc" {
					t.Errorf("Expected proxy_configured short name 'pc', got '%s'", proxyMetric.ShortName)
				}
				if proxyValue, ok := proxyMetric.Value.(bool); !ok {
					t.Errorf("Expected proxy_configured value to be bool, got %T", proxyMetric.Value)
				} else if proxyValue != tt.expectedProxyValue {
					t.Errorf("Expected proxy_configured value %v, got %v", tt.expectedProxyValue, proxyValue)
				}
			}

			// Validate provider metric
			providerMetric := findMetricByName(metrics.Metrics, "provider")
			if providerMetric == nil {
				t.Error("Expected to find 'provider' metric")
			} else {
				if providerMetric.ShortName != "prv" {
					t.Errorf("Expected provider short name 'prv', got '%s'", providerMetric.ShortName)
				}
			}

			// Validate environment metric
			envMetric := findMetricByName(metrics.Metrics, "environment")
			if envMetric == nil {
				t.Error("Expected to find 'environment' metric")
			} else {
				if envMetric.ShortName != "env" {
					t.Errorf("Expected environment short name 'env', got '%s'", envMetric.ShortName)
				}
			}

			// Validate region metric
			regionMetric := findMetricByName(metrics.Metrics, "region")
			if regionMetric == nil {
				t.Error("Expected to find 'region' metric")
			} else {
				if regionMetric.ShortName != "reg" {
					t.Errorf("Expected region short name 'reg', got '%s'", regionMetric.ShortName)
				}
			}

			// Custom validation
			if tt.validateFunc != nil {
				tt.validateFunc(t, metrics)
			}
		})
	}
}

func TestIdsecEnvironmentMetricsCollector_IsDynamicMetrics(t *testing.T) {
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

			collector := &IdsecEnvironmentMetricsCollector{
				cloudDetector: cloud.NewIdsecCloudEnvDetector(),
			}
			result := collector.IsDynamicMetrics()

			if result != tt.expected {
				t.Errorf("Expected IsDynamicMetrics() to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIdsecEnvironmentMetricsCollector_CollectorName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{
			name:     "success_returns_collector_name",
			expected: IdsecEnvironmentMetricsCollectorName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecEnvironmentMetricsCollector{
				cloudDetector: cloud.NewIdsecCloudEnvDetector(),
			}
			result := collector.CollectorName()

			if result != tt.expected {
				t.Errorf("Expected CollectorName() to return '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestIdsecEnvironmentMetricsCollector_CollectMetrics_MetricStructure(t *testing.T) {
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
					// Value can be any type, so we just check it exists
					if metric.Value == nil && metric.Name != "provider" && metric.Name != "environment" &&
						metric.Name != "region" {
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

			collector := &IdsecEnvironmentMetricsCollector{
				cloudDetector: cloud.NewIdsecCloudEnvDetector(),
			}
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
