package telemetry

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/encoders"
)

func TestNewIdsecSyncTelemetry(t *testing.T) {
	tests := []struct {
		name               string
		collectors         []collectors.IdsecMetricsCollector
		encoder            encoders.IdsecMetricsEncoder
		expectedCollectors int
		validateFunc       func(t *testing.T, telemetry IdsecTelemetry)
	}{
		{
			name: "success_creates_telemetry_with_single_collector",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "test1", shortName: "t1"},
			},
			encoder:            &mockEncoder{},
			expectedCollectors: 1,
		},
		{
			name: "success_creates_telemetry_with_multiple_collectors",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "test1", shortName: "t1"},
				&mockCollector{name: "test2", shortName: "t2"},
				&mockCollector{name: "test3", shortName: "t3"},
			},
			encoder:            &mockEncoder{},
			expectedCollectors: 3,
		},
		{
			name:               "success_creates_telemetry_with_empty_collectors",
			collectors:         []collectors.IdsecMetricsCollector{},
			encoder:            &mockEncoder{},
			expectedCollectors: 0,
		},
		{
			name:               "success_creates_telemetry_with_nil_collectors",
			collectors:         nil,
			encoder:            &mockEncoder{},
			expectedCollectors: 0,
		},
		{
			name: "success_creates_telemetry_with_nil_encoder",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "test1", shortName: "t1"},
			},
			encoder:            nil,
			expectedCollectors: 1,
		},
		{
			name: "success_stores_collectors_reference",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "env", shortName: "env"},
				&mockCollector{name: "meta", shortName: "meta"},
			},
			encoder:            &mockEncoder{},
			expectedCollectors: 2,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				if syncTelemetry.Collectors[0].CollectorName() != "env" {
					t.Errorf("Expected first collector name 'env', got '%s'", syncTelemetry.Collectors[0].CollectorName())
				}
				if syncTelemetry.Collectors[1].CollectorName() != "meta" {
					t.Errorf("Expected second collector name 'meta', got '%s'", syncTelemetry.Collectors[1].CollectorName())
				}
			},
		},
		{
			name: "success_stores_encoder_reference",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "test", shortName: "t"},
			},
			encoder:            &mockEncoder{encodedData: []byte("test-data")},
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				mockEnc := syncTelemetry.Encoder.(*mockEncoder)
				if string(mockEnc.encodedData) != "test-data" {
					t.Errorf("Expected encoder with data 'test-data', got '%s'", string(mockEnc.encodedData))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			telemetry := NewIdsecSyncTelemetry(tt.collectors, tt.encoder)

			if telemetry == nil {
				t.Error("Expected non-nil telemetry")
				return
			}

			syncTelemetry, ok := telemetry.(*IdsecSyncTelemetry)
			if !ok {
				t.Error("Expected telemetry to be of type *IdsecSyncTelemetry")
				return
			}

			if len(syncTelemetry.Collectors) != tt.expectedCollectors {
				t.Errorf("Expected %d collectors, got %d", tt.expectedCollectors, len(syncTelemetry.Collectors))
			}

			if syncTelemetry.Encoder != tt.encoder {
				t.Error("Expected encoder to match provided encoder")
			}

			if syncTelemetry.lastCollectedEncoded != nil {
				t.Error("Expected lastCollectedEncoded to be nil on initialization")
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, telemetry)
			}
		})
	}
}

func TestNewDefaultIdsecSyncTelemetry(t *testing.T) {
	tests := []struct {
		name               string
		expectedCollectors int
		validateFunc       func(t *testing.T, telemetry IdsecTelemetry)
	}{
		{
			name:               "success_creates_telemetry_with_default_collectors",
			expectedCollectors: 3,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)

				// Verify environment collector
				if _, ok := syncTelemetry.Collectors[0].(*collectors.IdsecEnvironmentMetricsCollector); !ok {
					t.Error("Expected first collector to be IdsecEnvironmentMetricsCollector")
				}

				// Verify metadata collector
				if _, ok := syncTelemetry.Collectors[1].(*collectors.IdsecMetadataMetricsCollector); !ok {
					t.Error("Expected second collector to be IdsecMetadataMetricsCollector")
				}

				// Verify OS collector
				if _, ok := syncTelemetry.Collectors[2].(*collectors.IdsecOSMetricsCollector); !ok {
					t.Error("Expected third collector to be IdsecOSMetricsCollector")
				}
			},
		},
		{
			name:               "success_creates_telemetry_with_header_encoder",
			expectedCollectors: 3,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				if _, ok := syncTelemetry.Encoder.(*encoders.IdsecTelemetryHeaderMetricsEncoder); !ok {
					t.Error("Expected encoder to be IdsecTelemetryHeaderMetricsEncoder")
				}
			},
		},
		{
			name:               "success_initializes_with_nil_last_collected_metrics",
			expectedCollectors: 3,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				if syncTelemetry.lastCollectedEncoded != nil {
					t.Error("Expected lastCollectedEncoded to be nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			telemetry := NewDefaultIdsecSyncTelemetry()

			if telemetry == nil {
				t.Error("Expected non-nil telemetry")
				return
			}

			syncTelemetry, ok := telemetry.(*IdsecSyncTelemetry)
			if !ok {
				t.Error("Expected telemetry to be of type *IdsecSyncTelemetry")
				return
			}

			if len(syncTelemetry.Collectors) != tt.expectedCollectors {
				t.Errorf("Expected %d collectors, got %d", tt.expectedCollectors, len(syncTelemetry.Collectors))
			}

			if syncTelemetry.Encoder == nil {
				t.Error("Expected non-nil encoder")
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, telemetry)
			}
		})
	}
}

func TestNewLimitedIdsecSyncTelemetry(t *testing.T) {
	tests := []struct {
		name               string
		expectedCollectors int
		validateFunc       func(t *testing.T, telemetry IdsecTelemetry)
	}{
		{
			name:               "success_creates_telemetry_with_limited_collectors",
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)

				// Verify only metadata collector is present
				if _, ok := syncTelemetry.Collectors[0].(*collectors.IdsecMetadataMetricsCollector); !ok {
					t.Error("Expected first collector to be IdsecMetadataMetricsCollector")
				}
			},
		},
		{
			name:               "success_creates_telemetry_with_header_encoder",
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				if _, ok := syncTelemetry.Encoder.(*encoders.IdsecTelemetryHeaderMetricsEncoder); !ok {
					t.Error("Expected encoder to be IdsecTelemetryHeaderMetricsEncoder")
				}
			},
		},
		{
			name:               "success_initializes_with_nil_last_collected_encoded",
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				if syncTelemetry.lastCollectedEncoded != nil {
					t.Error("Expected lastCollectedEncoded to be nil")
				}
			},
		},
		{
			name:               "success_initializes_with_empty_last_collected_metrics_map",
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				if syncTelemetry.lastCollectedMetrics == nil {
					t.Error("Expected lastCollectedMetrics to be initialized")
					return
				}
				if len(syncTelemetry.lastCollectedMetrics) != 0 {
					t.Errorf("Expected empty lastCollectedMetrics map, got %d entries", len(syncTelemetry.lastCollectedMetrics))
				}
			},
		},
		{
			name:               "success_excludes_environment_collector",
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				for _, collector := range syncTelemetry.Collectors {
					if _, ok := collector.(*collectors.IdsecEnvironmentMetricsCollector); ok {
						t.Error("Expected no IdsecEnvironmentMetricsCollector in limited telemetry")
					}
				}
			},
		},
		{
			name:               "success_excludes_os_collector",
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				for _, collector := range syncTelemetry.Collectors {
					if _, ok := collector.(*collectors.IdsecOSMetricsCollector); ok {
						t.Error("Expected no IdsecOSMetricsCollector in limited telemetry")
					}
				}
			},
		},
		{
			name:               "success_returns_idsec_telemetry_interface",
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				// Verify that returned type implements IdsecTelemetry interface
				_, canCollect := telemetry.(interface{ CollectAndEncodeMetrics() ([]byte, error) })
				if !canCollect {
					t.Error("Expected telemetry to implement CollectAndEncodeMetrics method")
				}

				_, canFindCollector := telemetry.(interface {
					CollectorByName(string) collectors.IdsecMetricsCollector
				})
				if !canFindCollector {
					t.Error("Expected telemetry to implement CollectorByName method")
				}
			},
		},
		{
			name:               "success_collectors_slice_is_not_nil",
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				if syncTelemetry.Collectors == nil {
					t.Error("Expected Collectors slice to be non-nil")
				}
			},
		},
		{
			name:               "success_encoder_is_not_nil",
			expectedCollectors: 1,
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				syncTelemetry := telemetry.(*IdsecSyncTelemetry)
				if syncTelemetry.Encoder == nil {
					t.Error("Expected Encoder to be non-nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			telemetry := NewLimitedIdsecSyncTelemetry()

			if telemetry == nil {
				t.Error("Expected non-nil telemetry")
				return
			}

			syncTelemetry, ok := telemetry.(*IdsecSyncTelemetry)
			if !ok {
				t.Error("Expected telemetry to be of type *IdsecSyncTelemetry")
				return
			}

			if len(syncTelemetry.Collectors) != tt.expectedCollectors {
				t.Errorf("Expected %d collectors, got %d", tt.expectedCollectors, len(syncTelemetry.Collectors))
			}

			if syncTelemetry.Encoder == nil {
				t.Error("Expected non-nil encoder")
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, telemetry)
			}
		})
	}
}

func TestIdsecSyncTelemetry_CollectAndEncodeMetrics(t *testing.T) {
	tests := []struct {
		name            string
		collectors      []collectors.IdsecMetricsCollector
		encoder         encoders.IdsecMetricsEncoder
		forceCollection bool
		lastMetrics     []byte
		expectedData    []byte
		expectedError   bool
		validateFunc    func(t *testing.T, telemetry *IdsecSyncTelemetry, result []byte)
	}{
		{
			name: "success_collects_and_encodes_single_collector",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics: []collectors.IdsecMetric{
							{ShortName: "m1", Value: "v1"},
						},
					},
				},
			},
			encoder:         &mockEncoder{encodedData: []byte("encoded-data")},
			forceCollection: false,
			expectedData:    []byte("encoded-data"),
			expectedError:   false,
		},
		{
			name: "success_collects_and_encodes_multiple_collectors",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test1",
					shortName: "t1",
					metrics: &collectors.IdsecMetrics{
						ShortName: "t1",
						Metrics: []collectors.IdsecMetric{
							{ShortName: "m1", Value: "v1"},
						},
					},
				},
				&mockCollector{
					name:      "test2",
					shortName: "t2",
					metrics: &collectors.IdsecMetrics{
						ShortName: "t2",
						Metrics: []collectors.IdsecMetric{
							{ShortName: "m2", Value: "v2"},
						},
					},
				},
			},
			encoder:         &mockEncoder{encodedData: []byte("multi-encoded")},
			forceCollection: false,
			expectedData:    []byte("multi-encoded"),
			expectedError:   false,
		},
		{
			name: "error_collector_returns_error",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					err:       errors.New("collection failed"),
				},
			},
			encoder:         &mockEncoder{},
			forceCollection: false,
			expectedError:   true,
		},
		{
			name: "error_encoder_returns_error",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:         &mockEncoder{err: errors.New("encoding failed")},
			forceCollection: false,
			expectedError:   true,
		},
		{
			name: "success_returns_cached_metrics_for_static_collectors",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:         &mockEncoder{encodedData: []byte("new-data")},
			forceCollection: false,
			lastMetrics:     []byte("cached-data"),
			expectedData:    []byte("cached-data"),
			expectedError:   false,
		},
		{
			name: "success_force_collection_overrides_cache",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					isDynamic: true,
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:         &mockEncoder{encodedData: []byte("new-data")},
			forceCollection: true,
			lastMetrics:     []byte("cached-data"),
			expectedData:    []byte("new-data"),
			expectedError:   false,
		},
		{
			name: "success_dynamic_collector_bypasses_cache",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					isDynamic: true,
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:         &mockEncoder{encodedData: []byte("new-data")},
			forceCollection: false,
			lastMetrics:     []byte("cached-data"),
			expectedData:    []byte("new-data"),
			expectedError:   false,
		},
		{
			name: "success_mixed_static_and_dynamic_collectors_bypasses_cache",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "static",
					shortName: "s",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "s",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
				&mockCollector{
					name:      "dynamic",
					shortName: "d",
					isDynamic: true,
					metrics: &collectors.IdsecMetrics{
						ShortName: "d",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m2", Value: "v2"}},
					},
				},
			},
			encoder:         &mockEncoder{encodedData: []byte("mixed-data")},
			forceCollection: false,
			lastMetrics:     []byte("cached-data"),
			expectedData:    []byte("mixed-data"),
			expectedError:   false,
		},
		{
			name:            "success_empty_collectors_returns_empty_encoded",
			collectors:      []collectors.IdsecMetricsCollector{},
			encoder:         &mockEncoder{encodedData: []byte("")},
			forceCollection: false,
			expectedData:    []byte(""),
			expectedError:   false,
		},
		{
			name: "success_collector_returns_nil_metrics",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					metrics:   nil,
				},
			},
			encoder:         &mockEncoder{encodedData: []byte("nil-metrics")},
			forceCollection: false,
			expectedData:    []byte("nil-metrics"),
			expectedError:   false,
		},
		{
			name: "success_first_collection_with_static_collectors",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:         &mockEncoder{encodedData: []byte("first-collection")},
			forceCollection: false,
			lastMetrics:     nil,
			expectedData:    []byte("first-collection"),
			expectedError:   false,
		},
		{
			name: "success_caches_result_after_collection",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:         &mockEncoder{encodedData: []byte("cached-after-collection")},
			forceCollection: false,
			lastMetrics:     nil,
			expectedData:    []byte("cached-after-collection"),
			expectedError:   false,
			validateFunc: func(t *testing.T, telemetry *IdsecSyncTelemetry, result []byte) {
				if telemetry.lastCollectedEncoded == nil {
					t.Error("Expected lastCollectedEncoded to be set after collection")
					return
				}
				if !reflect.DeepEqual(telemetry.lastCollectedEncoded, result) {
					t.Error("Expected lastCollectedEncoded to match returned result")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			telemetry := &IdsecSyncTelemetry{
				Collectors:           tt.collectors,
				Encoder:              tt.encoder,
				lastCollectedMetrics: make(map[string]*collectors.IdsecMetrics),
				lastCollectedEncoded: tt.lastMetrics,
			}

			result, err := telemetry.CollectAndEncodeMetrics()

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

			if !reflect.DeepEqual(result, tt.expectedData) {
				t.Errorf("Expected data %v, got %v", tt.expectedData, result)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, telemetry, result)
			}
		})
	}
}

func TestIdsecSyncTelemetry_CollectorByName(t *testing.T) {
	tests := []struct {
		name              string
		collectors        []collectors.IdsecMetricsCollector
		searchName        string
		expectedFound     bool
		expectedShortName string
		validateFunc      func(t *testing.T, collector collectors.IdsecMetricsCollector)
	}{
		{
			name: "success_finds_collector_by_name",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "test1", shortName: "t1"},
				&mockCollector{name: "test2", shortName: "t2"},
				&mockCollector{name: "test3", shortName: "t3"},
			},
			searchName:        "test2",
			expectedFound:     true,
			expectedShortName: "t2",
		},
		{
			name: "success_finds_first_collector",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "first", shortName: "f"},
				&mockCollector{name: "second", shortName: "s"},
			},
			searchName:        "first",
			expectedFound:     true,
			expectedShortName: "f",
		},
		{
			name: "success_finds_last_collector",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "first", shortName: "f"},
				&mockCollector{name: "last", shortName: "l"},
			},
			searchName:        "last",
			expectedFound:     true,
			expectedShortName: "l",
		},
		{
			name: "success_returns_nil_for_nonexistent_collector",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "test1", shortName: "t1"},
				&mockCollector{name: "test2", shortName: "t2"},
			},
			searchName:    "nonexistent",
			expectedFound: false,
		},
		{
			name:          "success_returns_nil_for_empty_collectors",
			collectors:    []collectors.IdsecMetricsCollector{},
			searchName:    "test",
			expectedFound: false,
		},
		{
			name: "success_returns_nil_for_empty_search_name",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "test", shortName: "t"},
			},
			searchName:    "",
			expectedFound: false,
		},
		{
			name: "success_case_sensitive_search",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "Test", shortName: "t"},
			},
			searchName:    "test",
			expectedFound: false,
		},
		{
			name: "success_exact_match_required",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "test-collector", shortName: "tc"},
			},
			searchName:    "test",
			expectedFound: false,
		},
		{
			name: "success_returns_first_match_with_duplicates",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "duplicate", shortName: "d1"},
				&mockCollector{name: "duplicate", shortName: "d2"},
			},
			searchName:        "duplicate",
			expectedFound:     true,
			expectedShortName: "d1",
		},
		{
			name: "success_validates_collector_type",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			searchName:        "test",
			expectedFound:     true,
			expectedShortName: "t",
			validateFunc: func(t *testing.T, collector collectors.IdsecMetricsCollector) {
				if _, ok := collector.(*mockCollector); !ok {
					t.Error("Expected collector to be of type *mockCollector")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			telemetry := &IdsecSyncTelemetry{
				Collectors:           tt.collectors,
				lastCollectedMetrics: make(map[string]*collectors.IdsecMetrics),
			}

			result := telemetry.CollectorByName(tt.searchName)

			if tt.expectedFound {
				if result == nil {
					t.Error("Expected to find collector, got nil")
					return
				}

				mockColl := result.(*mockCollector)
				if mockColl.shortName != tt.expectedShortName {
					t.Errorf("Expected short name '%s', got '%s'", tt.expectedShortName, mockColl.shortName)
				}

				if tt.validateFunc != nil {
					tt.validateFunc(t, result)
				}
			} else {
				if result != nil {
					t.Errorf("Expected nil collector, got %+v", result)
				}
			}
		})
	}
}

func TestIdsecSyncTelemetry_InterfaceCompliance(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, telemetry IdsecTelemetry)
	}{
		{
			name: "success_implements_idsec_telemetry_interface",
			validateFunc: func(t *testing.T, telemetry IdsecTelemetry) {
				if telemetry == nil {
					t.Error("Expected non-nil telemetry")
					return
				}

				// Test CollectAndEncodeMetrics method
				_, err := telemetry.CollectAndEncodeMetrics()
				// Don't check error, just verify method exists and is callable
				_ = err

				// Test CollectorByName method
				collector := telemetry.CollectorByName("test")
				_ = collector
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			telemetry := NewIdsecSyncTelemetry(
				[]collectors.IdsecMetricsCollector{
					&mockCollector{name: "test", shortName: "t"},
				},
				&mockEncoder{},
			)

			if tt.validateFunc != nil {
				tt.validateFunc(t, telemetry)
			}
		})
	}
}

func TestIdsecSyncTelemetry_ConcurrentCollectAndEncodeMetrics(t *testing.T) {
	tests := []struct {
		name          string
		collectors    []collectors.IdsecMetricsCollector
		encoder       encoders.IdsecMetricsEncoder
		goroutines    int
		iterations    int
		expectedError bool
		validateFunc  func(t *testing.T, results [][]byte, errors []error)
	}{
		{
			name: "success_concurrent_collection_with_static_collectors",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "static1",
					shortName: "s1",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "s1",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
				&mockCollector{
					name:      "static2",
					shortName: "s2",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "s2",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m2", Value: "v2"}},
					},
				},
			},
			encoder:       &mockEncoder{encodedData: []byte("concurrent-static")},
			goroutines:    10,
			iterations:    5,
			expectedError: false,
			validateFunc: func(t *testing.T, results [][]byte, errors []error) {
				// All results should be identical for static collectors
				firstResult := results[0]
				for i, result := range results {
					if !reflect.DeepEqual(result, firstResult) {
						t.Errorf("Result %d differs from first result: expected %v, got %v", i, firstResult, result)
					}
				}
			},
		},
		{
			name: "success_concurrent_collection_with_dynamic_collectors",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "dynamic",
					shortName: "d",
					isDynamic: true,
					metrics: &collectors.IdsecMetrics{
						ShortName: "d",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:       &mockEncoder{encodedData: []byte("concurrent-dynamic")},
			goroutines:    10,
			iterations:    5,
			expectedError: false,
			validateFunc: func(t *testing.T, results [][]byte, errors []error) {
				// All results should be the same encoded data
				for i, result := range results {
					if string(result) != "concurrent-dynamic" {
						t.Errorf("Result %d has unexpected data: got %s", i, string(result))
					}
				}
			},
		},
		{
			name: "success_concurrent_collection_with_mixed_collectors",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "static",
					shortName: "s",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "s",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
				&mockCollector{
					name:      "dynamic",
					shortName: "d",
					isDynamic: true,
					metrics: &collectors.IdsecMetrics{
						ShortName: "d",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m2", Value: "v2"}},
					},
				},
			},
			encoder:       &mockEncoder{encodedData: []byte("concurrent-mixed")},
			goroutines:    20,
			iterations:    3,
			expectedError: false,
			validateFunc: func(t *testing.T, results [][]byte, errors []error) {
				// Verify no errors occurred
				for i, err := range errors {
					if err != nil {
						t.Errorf("Goroutine %d returned error: %v", i, err)
					}
				}
			},
		},
		{
			name: "success_concurrent_collection_handles_race_conditions",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:       &mockEncoder{encodedData: []byte("race-test")},
			goroutines:    50,
			iterations:    10,
			expectedError: false,
			validateFunc: func(t *testing.T, results [][]byte, errors []error) {
				// Verify all results are consistent
				if len(results) != 50*10 {
					t.Errorf("Expected %d results, got %d", 50*10, len(results))
				}
				// All should return the same cached result
				firstResult := results[0]
				for i, result := range results {
					if !reflect.DeepEqual(result, firstResult) {
						t.Errorf("Result %d differs from first result", i)
					}
				}
			},
		},
		{
			name: "success_no_data_race_on_last_collected_metrics_map",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "collector1",
					shortName: "c1",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "c1",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
				&mockCollector{
					name:      "collector2",
					shortName: "c2",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "c2",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m2", Value: "v2"}},
					},
				},
			},
			encoder:       &mockEncoder{encodedData: []byte("map-race-test")},
			goroutines:    30,
			iterations:    5,
			expectedError: false,
			validateFunc: func(t *testing.T, results [][]byte, errors []error) {
				// Just verify no panics or errors occurred
				for i, err := range errors {
					if err != nil {
						t.Errorf("Goroutine %d returned error: %v", i, err)
					}
				}
			},
		},
		{
			name: "success_concurrent_first_collection",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test",
					shortName: "t",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "t",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:       &mockEncoder{encodedData: []byte("first-concurrent")},
			goroutines:    15,
			iterations:    1,
			expectedError: false,
			validateFunc: func(t *testing.T, results [][]byte, errors []error) {
				// All goroutines racing for first collection should get same result
				firstResult := results[0]
				for i, result := range results {
					if !reflect.DeepEqual(result, firstResult) {
						t.Errorf("Result %d differs from first result during initial concurrent collection", i)
					}
				}
			},
		},
		{
			name: "success_high_concurrency_stress_test",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "stress",
					shortName: "s",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "s",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder:       &mockEncoder{encodedData: []byte("stress-test")},
			goroutines:    100,
			iterations:    10,
			expectedError: false,
			validateFunc: func(t *testing.T, results [][]byte, errors []error) {
				// Verify correct number of results
				if len(results) != 100*10 {
					t.Errorf("Expected %d results, got %d", 100*10, len(results))
				}
				// Verify no errors
				for i, err := range errors {
					if err != nil {
						t.Errorf("Goroutine %d returned error: %v", i, err)
					}
				}
			},
		},
		{
			name:          "success_concurrent_with_empty_collectors",
			collectors:    []collectors.IdsecMetricsCollector{},
			encoder:       &mockEncoder{encodedData: []byte("")},
			goroutines:    10,
			iterations:    5,
			expectedError: false,
			validateFunc: func(t *testing.T, results [][]byte, errors []error) {
				// Should handle empty collectors without issues
				for i, err := range errors {
					if err != nil {
						t.Errorf("Goroutine %d returned error: %v", i, err)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Not using t.Parallel() here because we're testing concurrency explicitly
			// and want to control the test execution

			telemetry := &IdsecSyncTelemetry{
				Collectors:           tt.collectors,
				Encoder:              tt.encoder,
				lastCollectedMetrics: make(map[string]*collectors.IdsecMetrics),
			}

			var wg sync.WaitGroup
			results := make([][]byte, tt.goroutines*tt.iterations)
			errors := make([]error, tt.goroutines*tt.iterations)
			resultIndex := 0
			var indexMutex sync.Mutex

			for i := 0; i < tt.goroutines; i++ {
				wg.Add(1)
				go func(goroutineID int) {
					defer wg.Done()
					for j := 0; j < tt.iterations; j++ {
						result, err := telemetry.CollectAndEncodeMetrics()

						// Store result with mutex to avoid race on result slice
						indexMutex.Lock()
						idx := resultIndex
						resultIndex++
						results[idx] = result
						errors[idx] = err
						indexMutex.Unlock()
					}
				}(i)
			}

			wg.Wait()

			// Validate results
			if tt.validateFunc != nil {
				tt.validateFunc(t, results, errors)
			}

			// General validation: check for expected errors
			hasError := false
			for _, err := range errors {
				if err != nil {
					hasError = true
					break
				}
			}

			if tt.expectedError && !hasError {
				t.Error("Expected at least one error, got none")
			}
			if !tt.expectedError && hasError {
				t.Error("Expected no errors, got at least one")
			}
		})
	}
}

func TestIdsecSyncTelemetry_MutexProtectsLastCollectedMetrics(t *testing.T) {
	tests := []struct {
		name         string
		collectors   []collectors.IdsecMetricsCollector
		encoder      encoders.IdsecMetricsEncoder
		validateFunc func(t *testing.T, telemetry *IdsecSyncTelemetry)
	}{
		{
			name: "success_mutex_protects_map_writes",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "test1",
					shortName: "t1",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "t1",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
				&mockCollector{
					name:      "test2",
					shortName: "t2",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "t2",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m2", Value: "v2"}},
					},
				},
			},
			encoder: &mockEncoder{encodedData: []byte("mutex-test")},
			validateFunc: func(t *testing.T, telemetry *IdsecSyncTelemetry) {
				var wg sync.WaitGroup
				iterations := 50

				for i := 0; i < iterations; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, err := telemetry.CollectAndEncodeMetrics()
						if err != nil {
							t.Errorf("Unexpected error during concurrent collection: %v", err)
						}
					}()
				}

				wg.Wait()

				// Verify map integrity after concurrent access
				if len(telemetry.lastCollectedMetrics) != 2 {
					t.Errorf("Expected 2 entries in lastCollectedMetrics, got %d", len(telemetry.lastCollectedMetrics))
				}

				// Verify collectors are in the map
				if _, ok := telemetry.lastCollectedMetrics["test1"]; !ok {
					t.Error("Expected 'test1' collector in lastCollectedMetrics")
				}
				if _, ok := telemetry.lastCollectedMetrics["test2"]; !ok {
					t.Error("Expected 'test2' collector in lastCollectedMetrics")
				}
			},
		},
		{
			name: "success_mutex_protects_map_reads",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "static",
					shortName: "s",
					isDynamic: false,
					metrics: &collectors.IdsecMetrics{
						ShortName: "s",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder: &mockEncoder{encodedData: []byte("read-test")},
			validateFunc: func(t *testing.T, telemetry *IdsecSyncTelemetry) {
				// First collection to populate cache
				_, err := telemetry.CollectAndEncodeMetrics()
				if err != nil {
					t.Fatalf("Initial collection failed: %v", err)
				}

				var wg sync.WaitGroup
				iterations := 100
				errors := make([]error, iterations)

				for i := 0; i < iterations; i++ {
					wg.Add(1)
					go func(idx int) {
						defer wg.Done()
						_, err := telemetry.CollectAndEncodeMetrics()
						errors[idx] = err
					}(i)
				}

				wg.Wait()

				// Verify no errors occurred during concurrent reads
				for i, err := range errors {
					if err != nil {
						t.Errorf("Read operation %d failed: %v", i, err)
					}
				}
			},
		},
		{
			name: "success_mutex_prevents_concurrent_map_writes",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{
					name:      "dynamic",
					shortName: "d",
					isDynamic: true,
					metrics: &collectors.IdsecMetrics{
						ShortName: "d",
						Metrics:   []collectors.IdsecMetric{{ShortName: "m1", Value: "v1"}},
					},
				},
			},
			encoder: &mockEncoder{encodedData: []byte("write-test")},
			validateFunc: func(t *testing.T, telemetry *IdsecSyncTelemetry) {
				var wg sync.WaitGroup
				iterations := 75

				for i := 0; i < iterations; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, _ = telemetry.CollectAndEncodeMetrics()
					}()
				}

				wg.Wait()

				// After all concurrent writes, map should still be valid
				if telemetry.lastCollectedMetrics == nil {
					t.Error("lastCollectedMetrics map became nil")
				}

				// Verify we can still access the map without panic
				if _, ok := telemetry.lastCollectedMetrics["dynamic"]; !ok {
					t.Error("Expected 'dynamic' collector in map after concurrent writes")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Not using t.Parallel() for mutex tests to have better control

			telemetry := &IdsecSyncTelemetry{
				Collectors:           tt.collectors,
				Encoder:              tt.encoder,
				lastCollectedMetrics: make(map[string]*collectors.IdsecMetrics),
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, telemetry)
			}
		})
	}
}

func TestIdsecSyncTelemetry_ConcurrentCollectorByName(t *testing.T) {
	tests := []struct {
		name         string
		collectors   []collectors.IdsecMetricsCollector
		searchNames  []string
		goroutines   int
		validateFunc func(t *testing.T, results []collectors.IdsecMetricsCollector)
	}{
		{
			name: "success_concurrent_collector_lookup",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "test1", shortName: "t1"},
				&mockCollector{name: "test2", shortName: "t2"},
				&mockCollector{name: "test3", shortName: "t3"},
			},
			searchNames: []string{"test1", "test2", "test3", "nonexistent"},
			goroutines:  20,
			validateFunc: func(t *testing.T, results []collectors.IdsecMetricsCollector) {
				// Verify results are consistent
				foundCount := 0
				nilCount := 0
				for _, result := range results {
					if result != nil {
						foundCount++
					} else {
						nilCount++
					}
				}

				// We expect some found and some nil (for "nonexistent")
				if foundCount == 0 {
					t.Error("Expected some collectors to be found")
				}
				if nilCount == 0 {
					t.Error("Expected some nil results for nonexistent collector")
				}
			},
		},
		{
			name: "success_concurrent_same_name_lookup",
			collectors: []collectors.IdsecMetricsCollector{
				&mockCollector{name: "target", shortName: "t"},
			},
			searchNames: []string{"target"},
			goroutines:  50,
			validateFunc: func(t *testing.T, results []collectors.IdsecMetricsCollector) {
				// All results should be non-nil and point to same collector
				for i, result := range results {
					if result == nil {
						t.Errorf("Result %d is nil, expected non-nil collector", i)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			telemetry := &IdsecSyncTelemetry{
				Collectors:           tt.collectors,
				lastCollectedMetrics: make(map[string]*collectors.IdsecMetrics),
			}

			var wg sync.WaitGroup
			results := make([]collectors.IdsecMetricsCollector, tt.goroutines)

			for i := 0; i < tt.goroutines; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					searchName := tt.searchNames[idx%len(tt.searchNames)]
					results[idx] = telemetry.CollectorByName(searchName)
				}(i)
			}

			wg.Wait()

			if tt.validateFunc != nil {
				tt.validateFunc(t, results)
			}
		})
	}
}

// Mock implementations for testing

type mockCollector struct {
	name      string
	shortName string
	isDynamic bool
	metrics   *collectors.IdsecMetrics
	err       error
}

func (m *mockCollector) CollectorName() string {
	return m.name
}

func (m *mockCollector) CollectorShortName() string {
	return m.shortName
}

func (m *mockCollector) IsDynamicMetrics() bool {
	return m.isDynamic
}

func (m *mockCollector) CollectMetrics() (*collectors.IdsecMetrics, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.metrics, nil
}

type mockEncoder struct {
	encodedData []byte
	err         error
}

func (m *mockEncoder) EncodeMetrics(metrics []*collectors.IdsecMetrics) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.encodedData, nil
}
