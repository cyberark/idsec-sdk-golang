package encoders

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

func TestNewIdsecTelemetryHeaderMetricsEncoder(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "success_creates_encoder_instance",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoder := NewIdsecTelemetryHeaderMetricsEncoder()

			if encoder == nil {
				t.Error("Expected non-nil encoder")
			}

			if _, ok := encoder.(*IdsecTelemetryHeaderMetricsEncoder); !ok && tt.expected {
				t.Error("Expected encoder to be of type *IdsecTelemetryHeaderMetricsEncoder")
			}
		})
	}
}

func TestIdsecTelemetryHeaderMetricsEncoder_toString(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected string
	}{
		{
			name:     "success_converts_string",
			value:    "test-value",
			expected: "test-value",
		},
		{
			name:     "success_converts_int",
			value:    42,
			expected: "42",
		},
		{
			name:     "success_converts_int8",
			value:    int8(127),
			expected: "127",
		},
		{
			name:     "success_converts_int16",
			value:    int16(32767),
			expected: "32767",
		},
		{
			name:     "success_converts_int32",
			value:    int32(2147483647),
			expected: "2147483647",
		},
		{
			name:     "success_converts_int64",
			value:    int64(9223372036854775807),
			expected: "9223372036854775807",
		},
		{
			name:     "success_converts_uint",
			value:    uint(42),
			expected: "42",
		},
		{
			name:     "success_converts_uint8",
			value:    uint8(255),
			expected: "255",
		},
		{
			name:     "success_converts_uint16",
			value:    uint16(65535),
			expected: "65535",
		},
		{
			name:     "success_converts_uint32",
			value:    uint32(4294967295),
			expected: "4294967295",
		},
		{
			name:     "success_converts_uint64",
			value:    uint64(18446744073709551615),
			expected: "18446744073709551615",
		},
		{
			name:     "success_converts_float32",
			value:    float32(3.14),
			expected: "3.14",
		},
		{
			name:     "success_converts_float64",
			value:    float64(2.718281828),
			expected: "2.718281828",
		},
		{
			name:     "success_converts_bool_true",
			value:    true,
			expected: "true",
		},
		{
			name:     "success_converts_bool_false",
			value:    false,
			expected: "false",
		},
		{
			name:     "success_converts_nil_to_empty_string",
			value:    nil,
			expected: "",
		},
		{
			name:     "success_converts_map_to_json",
			value:    map[string]string{"key": "value"},
			expected: `{"key":"value"}`,
		},
		{
			name:     "success_converts_slice_to_json",
			value:    []string{"item1", "item2"},
			expected: `["item1","item2"]`,
		},
		{
			name: "success_converts_struct_to_json",
			value: struct {
				Name  string `json:"name"`
				Value int    `json:"value"`
			}{
				Name:  "test",
				Value: 123,
			},
			expected: `{"name":"test","value":123}`,
		},
		{
			name:     "success_converts_empty_string",
			value:    "",
			expected: "",
		},
		{
			name:     "success_converts_zero_int",
			value:    0,
			expected: "0",
		},
		{
			name:     "success_converts_negative_int",
			value:    -42,
			expected: "-42",
		},
		{
			name:     "success_converts_negative_float",
			value:    -3.14,
			expected: "-3.14",
		},
		{
			name:     "success_converts_empty_map_to_json",
			value:    map[string]string{},
			expected: `{}`,
		},
		{
			name:     "success_converts_empty_slice_to_json",
			value:    []string{},
			expected: `[]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoder := &IdsecTelemetryHeaderMetricsEncoder{}
			result := encoder.toString(tt.value)

			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestIdsecTelemetryHeaderMetricsEncoder_EncodeMetrics(t *testing.T) {
	tests := []struct {
		name          string
		metrics       []*collectors.IdsecMetrics
		expectedData  string
		expectedError bool
		validateFunc  func(t *testing.T, result []byte)
	}{
		{
			name: "success_encodes_single_metric_group_single_metric",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "metric1",
							Value:     "value1",
						},
					},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s&coll1.metric1=value1", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_single_metric_group_multiple_metrics",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "metric1",
							Value:     "value1",
						},
						{
							ShortName: "metric2",
							Value:     42,
						},
					},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s&coll1.metric1=value1&coll1.metric2=42", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_multiple_metric_groups",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "metric1",
							Value:     "value1",
						},
					},
				},
				{
					ShortName: "coll2",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "metric2",
							Value:     "value2",
						},
					},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s&coll1.metric1=value1&coll2.metric2=value2", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_metrics_with_different_types",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "str",
							Value:     "text",
						},
						{
							ShortName: "int",
							Value:     123,
						},
						{
							ShortName: "float",
							Value:     3.14,
						},
						{
							ShortName: "bool",
							Value:     true,
						},
					},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s&coll1.str=text&coll1.int=123&coll1.float=3.14&coll1.bool=true", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name:          "success_encodes_empty_metrics_slice",
			metrics:       []*collectors.IdsecMetrics{},
			expectedData:  fmt.Sprintf("sn=%s", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name:          "success_encodes_nil_metrics_slice",
			metrics:       nil,
			expectedData:  fmt.Sprintf("sn=%s", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_metric_group_with_no_metrics",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics:   []collectors.IdsecMetric{},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_metric_with_special_characters",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "metric1",
							Value:     "value with spaces",
						},
						{
							ShortName: "metric2",
							Value:     "value&with=special",
						},
					},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s&coll1.metric1=value with spaces&coll1.metric2=value&with=special", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_metric_with_json_object",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "metric1",
							Value:     map[string]string{"key": "value"},
						},
					},
				},
			},
			expectedData:  fmt.Sprintf(`sn=%s&coll1.metric1={"key":"value"}`, config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_metric_with_json_array",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "metric1",
							Value:     []string{"item1", "item2"},
						},
					},
				},
			},
			expectedData:  fmt.Sprintf(`sn=%s&coll1.metric1=["item1","item2"]`, config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_metric_with_nil_value",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "metric1",
							Value:     nil,
						},
					},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s&coll1.metric1=", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_metric_with_zero_values",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "coll1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "int",
							Value:     0,
						},
						{
							ShortName: "float",
							Value:     0.0,
						},
						{
							ShortName: "bool",
							Value:     false,
						},
						{
							ShortName: "str",
							Value:     "",
						},
					},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s&coll1.int=0&coll1.float=0&coll1.bool=false&coll1.str=", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_encodes_multiple_groups_multiple_metrics",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "sys",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "cpu",
							Value:     75,
						},
						{
							ShortName: "mem",
							Value:     85,
						},
					},
				},
				{
					ShortName: "app",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "req",
							Value:     1000,
						},
						{
							ShortName: "err",
							Value:     5,
						},
					},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s&sys.cpu=75&sys.mem=85&app.req=1000&app.err=5", config.IdsecToolInUse()),
			expectedError: false,
		},
		{
			name: "success_base64_encoding_is_correct",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "test",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "m1",
							Value:     "v1",
						},
					},
				},
			},
			expectedData:  fmt.Sprintf("sn=%s&test.m1=v1", config.IdsecToolInUse()),
			expectedError: false,
			validateFunc: func(t *testing.T, result []byte) {
				decoded, err := base64.StdEncoding.DecodeString(string(result))
				if err != nil {
					t.Errorf("Failed to decode base64: %v", err)
					return
				}
				expected := fmt.Sprintf("sn=%s&test.m1=v1", config.IdsecToolInUse())
				if string(decoded) != expected {
					t.Errorf("Expected decoded value '%s', got '%s'", expected, string(decoded))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoder := &IdsecTelemetryHeaderMetricsEncoder{}
			result, err := encoder.EncodeMetrics(tt.metrics)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Decode base64 to compare with expected data
			decoded, err := base64.StdEncoding.DecodeString(string(result))
			if err != nil {
				t.Errorf("Failed to decode base64 result: %v", err)
				return
			}

			if string(decoded) != tt.expectedData {
				t.Errorf("Expected decoded data '%s', got '%s'", tt.expectedData, string(decoded))
			}

			// Verify the result is valid base64
			if len(result) > 0 {
				_, err = base64.StdEncoding.DecodeString(string(result))
				if err != nil {
					t.Errorf("Result is not valid base64: %v", err)
				}
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecTelemetryHeaderMetricsEncoder_EncodeMetrics_Format(t *testing.T) {
	tests := []struct {
		name         string
		metrics      []*collectors.IdsecMetrics
		validateFunc func(t *testing.T, encoded string)
	}{
		{
			name: "success_format_follows_cyberark_standard",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "collector1",
					Metrics: []collectors.IdsecMetric{
						{
							ShortName: "metric1",
							Value:     "value1",
						},
						{
							ShortName: "metric2",
							Value:     "value2",
						},
					},
				},
			},
			validateFunc: func(t *testing.T, encoded string) {
				// Verify format: sn=ServiceName&CollectorShortName.MetricName=MetricValue&...
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Errorf("Failed to decode: %v", err)
					return
				}

				expected := fmt.Sprintf("sn=%s&collector1.metric1=value1&collector1.metric2=value2", config.IdsecToolInUse())
				if string(decoded) != expected {
					t.Errorf("Expected format '%s', got '%s'", expected, string(decoded))
				}
			},
		},
		{
			name: "success_ampersand_separator_between_metrics",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "c1",
					Metrics: []collectors.IdsecMetric{
						{ShortName: "m1", Value: "v1"},
						{ShortName: "m2", Value: "v2"},
						{ShortName: "m3", Value: "v3"},
					},
				},
			},
			validateFunc: func(t *testing.T, encoded string) {
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Errorf("Failed to decode: %v", err)
					return
				}

				// Count ampersands - should be (number of metrics) for sn= prefix + metrics
				ampersandCount := 0
				for _, c := range string(decoded) {
					if c == '&' {
						ampersandCount++
					}
				}

				if ampersandCount != 3 {
					t.Errorf("Expected 3 ampersands, got %d", ampersandCount)
				}
			},
		},
		{
			name: "success_dot_separator_between_collector_and_metric",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "collector",
					Metrics: []collectors.IdsecMetric{
						{ShortName: "metric", Value: "value"},
					},
				},
			},
			validateFunc: func(t *testing.T, encoded string) {
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Errorf("Failed to decode: %v", err)
					return
				}

				expected := fmt.Sprintf("sn=%s&collector.metric=value", config.IdsecToolInUse())
				if string(decoded) != expected {
					t.Errorf("Expected '%s', got '%s'", expected, string(decoded))
				}
			},
		},
		{
			name: "success_equals_separator_between_metric_and_value",
			metrics: []*collectors.IdsecMetrics{
				{
					ShortName: "c",
					Metrics: []collectors.IdsecMetric{
						{ShortName: "m", Value: "v"},
					},
				},
			},
			validateFunc: func(t *testing.T, encoded string) {
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Errorf("Failed to decode: %v", err)
					return
				}

				expected := fmt.Sprintf("sn=%s&c.m=v", config.IdsecToolInUse())
				if string(decoded) != expected {
					t.Errorf("Expected '%s', got '%s'", expected, string(decoded))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoder := &IdsecTelemetryHeaderMetricsEncoder{}
			result, err := encoder.EncodeMetrics(tt.metrics)

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, string(result))
			}
		})
	}
}

func TestIdsecTelemetryHeaderMetricsEncoder_Integration(t *testing.T) {
	tests := []struct {
		name         string
		setupMetrics func() []*collectors.IdsecMetrics
		validateFunc func(t *testing.T, encoded []byte)
	}{
		{
			name: "success_complete_encoding_cycle",
			setupMetrics: func() []*collectors.IdsecMetrics {
				return []*collectors.IdsecMetrics{
					{
						ShortName: "system",
						Metrics: []collectors.IdsecMetric{
							{ShortName: "cpu", Value: 75},
							{ShortName: "memory", Value: 85.5},
							{ShortName: "active", Value: true},
						},
					},
					{
						ShortName: "application",
						Metrics: []collectors.IdsecMetric{
							{ShortName: "requests", Value: 1000},
							{ShortName: "errors", Value: 5},
							{ShortName: "version", Value: "1.0.0"},
						},
					},
				}
			},
			validateFunc: func(t *testing.T, encoded []byte) {
				decoded, err := base64.StdEncoding.DecodeString(string(encoded))
				if err != nil {
					t.Errorf("Failed to decode: %v", err)
					return
				}

				expected := fmt.Sprintf("sn=%s&system.cpu=75&system.memory=85.5&system.active=true&application.requests=1000&application.errors=5&application.version=1.0.0", config.IdsecToolInUse())
				if string(decoded) != expected {
					t.Errorf("Expected '%s', got '%s'", expected, string(decoded))
				}

				// Verify it's valid base64
				if !isValidBase64(string(encoded)) {
					t.Error("Encoded result is not valid base64")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoder := NewIdsecTelemetryHeaderMetricsEncoder()
			metrics := tt.setupMetrics()
			result, err := encoder.EncodeMetrics(metrics)

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}

func TestIdsecTelemetryHeaderMetricsEncoder_InterfaceCompliance(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, encoder IdsecMetricsEncoder)
	}{
		{
			name: "success_implements_idsec_metrics_encoder_interface",
			validateFunc: func(t *testing.T, encoder IdsecMetricsEncoder) {
				if encoder == nil {
					t.Error("Expected non-nil encoder")
					return
				}

				// Test that EncodeMetrics method exists and works
				metrics := []*collectors.IdsecMetrics{
					{
						ShortName: "test",
						Metrics: []collectors.IdsecMetric{
							{ShortName: "m1", Value: "v1"},
						},
					},
				}

				result, err := encoder.EncodeMetrics(metrics)
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}

				if len(result) == 0 {
					t.Error("Expected non-empty result")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoder := NewIdsecTelemetryHeaderMetricsEncoder()

			if tt.validateFunc != nil {
				tt.validateFunc(t, encoder)
			}
		})
	}
}

func TestIdsecTelemetryHeaderMetricsEncoder_toString_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected string
	}{
		{
			name:     "success_handles_nested_map",
			value:    map[string]interface{}{"key": map[string]string{"nested": "value"}},
			expected: `{"key":{"nested":"value"}}`,
		},
		{
			name:     "success_handles_nested_slice",
			value:    []interface{}{[]string{"nested1", "nested2"}},
			expected: `[["nested1","nested2"]]`,
		},
		{
			name: "success_handles_complex_struct",
			value: struct {
				Name    string         `json:"name"`
				Tags    []string       `json:"tags"`
				Attrs   map[string]int `json:"attrs"`
				Enabled bool           `json:"enabled"`
			}{
				Name:    "test",
				Tags:    []string{"tag1", "tag2"},
				Attrs:   map[string]int{"count": 10},
				Enabled: true,
			},
			expected: `{"name":"test","tags":["tag1","tag2"],"attrs":{"count":10},"enabled":true}`,
		},
		{
			name:     "success_handles_pointer_to_int",
			value:    intPtr(42),
			expected: "42",
		},
		{
			name:     "success_handles_pointer_to_string",
			value:    stringPtr("test"),
			expected: `"test"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoder := &IdsecTelemetryHeaderMetricsEncoder{}
			result := encoder.toString(tt.value)

			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// Helper functions for tests

func intPtr(i int) *int {
	return &i
}

func stringPtr(s string) *string {
	return &s
}

func isValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// Benchmark tests

func BenchmarkIdsecTelemetryHeaderMetricsEncoder_toString_String(b *testing.B) {
	encoder := &IdsecTelemetryHeaderMetricsEncoder{}
	value := "test-value"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encoder.toString(value)
	}
}

func BenchmarkIdsecTelemetryHeaderMetricsEncoder_toString_Int(b *testing.B) {
	encoder := &IdsecTelemetryHeaderMetricsEncoder{}
	value := 42

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encoder.toString(value)
	}
}

func BenchmarkIdsecTelemetryHeaderMetricsEncoder_toString_Map(b *testing.B) {
	encoder := &IdsecTelemetryHeaderMetricsEncoder{}
	value := map[string]string{"key": "value"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encoder.toString(value)
	}
}

func BenchmarkIdsecTelemetryHeaderMetricsEncoder_EncodeMetrics_Single(b *testing.B) {
	encoder := &IdsecTelemetryHeaderMetricsEncoder{}
	metrics := []*collectors.IdsecMetrics{
		{
			ShortName: "test",
			Metrics: []collectors.IdsecMetric{
				{ShortName: "m1", Value: "v1"},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.EncodeMetrics(metrics)
	}
}

func BenchmarkIdsecTelemetryHeaderMetricsEncoder_EncodeMetrics_Multiple(b *testing.B) {
	encoder := &IdsecTelemetryHeaderMetricsEncoder{}
	metrics := []*collectors.IdsecMetrics{
		{
			ShortName: "sys",
			Metrics: []collectors.IdsecMetric{
				{ShortName: "cpu", Value: 75},
				{ShortName: "mem", Value: 85},
			},
		},
		{
			ShortName: "app",
			Metrics: []collectors.IdsecMetric{
				{ShortName: "req", Value: 1000},
				{ShortName: "err", Value: 5},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encoder.EncodeMetrics(metrics)
	}
}
