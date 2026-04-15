package collectors

import (
	"reflect"
	"testing"
)

// TestIdsecMetadataMetricsCollector_AddExtraContextField tests the AddExtraContextField method.
func TestIdsecMetadataMetricsCollector_AddExtraContextField(t *testing.T) {
	tests := []struct {
		name            string
		fieldName       string
		shortName       string
		value           string
		expectedValue   string
		expectedChanged bool
	}{
		{
			name:            "success_adds_context_field",
			fieldName:       "tool_name",
			shortName:       "tn",
			value:           "my_tool",
			expectedValue:   "my_tool",
			expectedChanged: true,
		},
		{
			name:            "success_adds_empty_value",
			fieldName:       "field_name",
			shortName:       "fn",
			value:           "",
			expectedValue:   "",
			expectedChanged: true,
		},
		{
			name:            "success_overwrites_existing_field",
			fieldName:       "context_field",
			shortName:       "cf",
			value:           "new_value",
			expectedValue:   "new_value",
			expectedChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				extraContextFields:        make(map[string]extraContextField),
				changedFromLastCollection: false,
			}

			collector.AddExtraContextField(tt.fieldName, tt.shortName, tt.value)

			value, _ := collector.GetExtraContextField(tt.shortName)
			if value != tt.expectedValue {
				t.Errorf("Expected value '%s', got '%s'", tt.expectedValue, value)
			}

			if collector.changedFromLastCollection != tt.expectedChanged {
				t.Errorf("Expected changedFromLastCollection %v, got %v", tt.expectedChanged, collector.changedFromLastCollection)
			}
		})
	}
}

// TestIdsecMetadataMetricsCollector_GetExtraContextField tests the GetExtraContextField method.
func TestIdsecMetadataMetricsCollector_GetExtraContextField(t *testing.T) {
	tests := []struct {
		name          string
		setupFields   map[string]extraContextField
		shortName     string
		expectedValue string
		expectedFound bool
	}{
		{
			name: "success_gets_existing_field",
			setupFields: map[string]extraContextField{
				"tn": {name: "tool_name", value: "my_tool"},
			},
			shortName:     "tn",
			expectedValue: "my_tool",
			expectedFound: true,
		},
		{
			name:          "success_returns_empty_for_nonexistent_field",
			setupFields:   make(map[string]extraContextField),
			shortName:     "nonexistent",
			expectedValue: "",
			expectedFound: false,
		},
		{
			name: "success_gets_multiple_fields",
			setupFields: map[string]extraContextField{
				"f1": {name: "field1", value: "value1"},
				"f2": {name: "field2", value: "value2"},
			},
			shortName:     "f2",
			expectedValue: "value2",
			expectedFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				extraContextFields: tt.setupFields,
			}

			value, found := collector.GetExtraContextField(tt.shortName)
			if value != tt.expectedValue {
				t.Errorf("Expected value '%s', got '%s'", tt.expectedValue, value)
			}
			if found != tt.expectedFound {
				t.Errorf("Expected found %v, got %v", tt.expectedFound, found)
			}
		})
	}
}

// TestIdsecMetadataMetricsCollector_ClearExtraContext tests the ClearExtraContext method.
func TestIdsecMetadataMetricsCollector_ClearExtraContext(t *testing.T) {
	tests := []struct {
		name            string
		setupCollector  func() *IdsecMetadataMetricsCollector
		expectedChanged bool
	}{
		{
			name: "success_clears_all_fields",
			setupCollector: func() *IdsecMetadataMetricsCollector {
				collector := &IdsecMetadataMetricsCollector{
					extraContextFields:        make(map[string]extraContextField),
					changedFromLastCollection: false,
				}
				collector.AddExtraContextField("field1", "f1", "value1")
				collector.AddExtraContextField("field2", "f2", "value2")
				collector.changedFromLastCollection = false
				return collector
			},
			expectedChanged: true,
		},
		{
			name: "success_clears_when_already_empty",
			setupCollector: func() *IdsecMetadataMetricsCollector {
				return &IdsecMetadataMetricsCollector{
					extraContextFields:        make(map[string]extraContextField),
					changedFromLastCollection: false,
				}
			},
			expectedChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := tt.setupCollector()
			collector.ClearExtraContext()

			if len(collector.extraContextFields) != 0 {
				t.Errorf("Expected empty extraContextFields, got %d fields", len(collector.extraContextFields))
			}

			if collector.changedFromLastCollection != tt.expectedChanged {
				t.Errorf("Expected changedFromLastCollection %v, got %v", tt.expectedChanged, collector.changedFromLastCollection)
			}
		})
	}
}

// TestIdsecMetadataMetricsCollector_CollectMetrics_WithExtraContext tests metrics collection with extra context fields.
func TestIdsecMetadataMetricsCollector_CollectMetrics_WithExtraContext(t *testing.T) {
	tests := []struct {
		name                 string
		setupCollector       func() *IdsecMetadataMetricsCollector
		expectedMetricsCount int
		validateFunc         func(t *testing.T, metrics *IdsecMetrics)
	}{
		{
			name: "success_includes_extra_context_in_metrics",
			setupCollector: func() *IdsecMetadataMetricsCollector {
				collector := &IdsecMetadataMetricsCollector{
					extraContextFields:        make(map[string]extraContextField),
					changedFromLastCollection: true,
				}
				collector.AddExtraContextField("tool_name", "tn", "my_tool")
				collector.AddExtraContextField("tool_version", "tv", "1.0.0")
				collector.AddExtraContextField("context_field", "cf", "some_value")
				return collector
			},
			expectedMetricsCount: 16, // 13 base + 3 extra fields
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				// Check for extra context metrics
				toolNameMetric := findMetricByName(metrics.Metrics, "tool_name")
				if toolNameMetric == nil {
					t.Error("Expected to find 'tool_name' metric")
				} else {
					if toolNameMetric.ShortName != "tn" {
						t.Errorf("Expected short name 'tn', got '%s'", toolNameMetric.ShortName)
					}
					if toolNameMetric.Value != "my_tool" {
						t.Errorf("Expected value 'my_tool', got '%v'", toolNameMetric.Value)
					}
				}

				toolVersionMetric := findMetricByName(metrics.Metrics, "tool_version")
				if toolVersionMetric == nil {
					t.Error("Expected to find 'tool_version' metric")
				} else {
					if toolVersionMetric.Value != "1.0.0" {
						t.Errorf("Expected value '1.0.0', got '%v'", toolVersionMetric.Value)
					}
				}
			},
		},
		{
			name: "success_no_extra_fields_when_not_set",
			setupCollector: func() *IdsecMetadataMetricsCollector {
				return &IdsecMetadataMetricsCollector{
					extraContextFields:        make(map[string]extraContextField),
					changedFromLastCollection: true,
				}
			},
			expectedMetricsCount: 13, // 13 base + 0 extra fields
			validateFunc: func(t *testing.T, metrics *IdsecMetrics) {
				// Verify no unexpected extra context metrics
				if len(metrics.Metrics) != 13 {
					t.Errorf("Expected exactly 13 metrics, got %d", len(metrics.Metrics))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := tt.setupCollector()
			metrics, err := collector.CollectMetrics()
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if metrics == nil {
				t.Fatal("Expected non-nil metrics")
			}

			if len(metrics.Metrics) != tt.expectedMetricsCount {
				t.Errorf("Expected %d metrics, got %d", tt.expectedMetricsCount, len(metrics.Metrics))
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, metrics)
			}
		})
	}
}

// TestIdsecMetadataMetricsCollector_ExtraContextIntegration tests the full workflow of extra context.
func TestIdsecMetadataMetricsCollector_ExtraContextIntegration(t *testing.T) {
	tests := []struct {
		name           string
		operations     func(collector *IdsecMetadataMetricsCollector)
		expectedFields map[string]string
	}{
		{
			name: "success_add_and_retrieve_multiple_fields",
			operations: func(collector *IdsecMetadataMetricsCollector) {
				collector.AddExtraContextField("field1", "f1", "value1")
				collector.AddExtraContextField("field2", "f2", "value2")
				collector.AddExtraContextField("field3", "f3", "value3")
			},
			expectedFields: map[string]string{
				"f1": "value1",
				"f2": "value2",
				"f3": "value3",
			},
		},
		{
			name: "success_overwrite_field",
			operations: func(collector *IdsecMetadataMetricsCollector) {
				collector.AddExtraContextField("field", "f", "initial")
				collector.AddExtraContextField("field", "f", "updated")
			},
			expectedFields: map[string]string{
				"f": "updated",
			},
		},
		{
			name: "success_add_clear_add",
			operations: func(collector *IdsecMetadataMetricsCollector) {
				collector.AddExtraContextField("field1", "f1", "value1")
				collector.ClearExtraContext()
				collector.AddExtraContextField("field2", "f2", "value2")
			},
			expectedFields: map[string]string{
				"f2": "value2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				extraContextFields:        make(map[string]extraContextField),
				changedFromLastCollection: false,
			}

			tt.operations(collector)

			for shortName, expectedValue := range tt.expectedFields {
				value, _ := collector.GetExtraContextField(shortName)
				if value != expectedValue {
					t.Errorf("For field '%s': expected value '%s', got '%s'", shortName, expectedValue, value)
				}
			}

			// Verify that fields not in expectedFields don't exist
			for shortName := range collector.extraContextFields {
				if _, exists := tt.expectedFields[shortName]; !exists {
					t.Errorf("Unexpected field '%s' found in extraContextFields", shortName)
				}
			}

			// Verify count
			if len(collector.extraContextFields) != len(tt.expectedFields) {
				t.Errorf("Expected %d fields, got %d", len(tt.expectedFields), len(collector.extraContextFields))
			}
		})
	}
}

// TestIdsecMetadataMetricsCollector_ExtraContextFieldStructure tests the internal structure.
func TestIdsecMetadataMetricsCollector_ExtraContextFieldStructure(t *testing.T) {
	tests := []struct {
		name           string
		fieldName      string
		shortName      string
		value          string
		expectedStruct extraContextField
	}{
		{
			name:      "success_stores_name_and_value",
			fieldName: "full_field_name",
			shortName: "ffn",
			value:     "test_value",
			expectedStruct: extraContextField{
				name:  "full_field_name",
				value: "test_value",
			},
		},
		{
			name:      "success_stores_empty_values",
			fieldName: "",
			shortName: "empty",
			value:     "",
			expectedStruct: extraContextField{
				name:  "",
				value: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			collector := &IdsecMetadataMetricsCollector{
				extraContextFields: make(map[string]extraContextField),
			}

			collector.AddExtraContextField(tt.fieldName, tt.shortName, tt.value)

			field, exists := collector.extraContextFields[tt.shortName]
			if !exists {
				t.Fatalf("Expected field '%s' to exist", tt.shortName)
			}

			if !reflect.DeepEqual(field, tt.expectedStruct) {
				t.Errorf("Expected struct %+v, got %+v", tt.expectedStruct, field)
			}
		})
	}
}
