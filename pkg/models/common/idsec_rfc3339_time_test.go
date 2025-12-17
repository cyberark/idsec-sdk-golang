package common

import (
	"reflect"
	"testing"
	"time"
)

func TestIdsecRFC3339Time_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name             string
		input            []byte
		expectedTime     IdsecRFC3339Time
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:          "success_valid_rfc3339_with_microseconds",
			input:         []byte(`"2023-01-01T12:00:00.123456Z"`),
			expectedTime:  IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.UTC)),
			expectedError: false,
		},
		{
			name:          "success_valid_rfc3339_without_microseconds",
			input:         []byte(`"2023-01-01T12:00:00.000000Z"`),
			expectedTime:  IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
			expectedError: false,
		},
		{
			name:          "success_valid_rfc3339_with_timezone_offset",
			input:         []byte(`"2023-01-01T12:00:00.123456+05:00"`),
			expectedTime:  IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.FixedZone("", 5*3600))),
			expectedError: false,
		},
		{
			name:          "success_valid_rfc3339_with_negative_timezone",
			input:         []byte(`"2023-01-01T12:00:00.123456-07:00"`),
			expectedTime:  IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.FixedZone("", -7*3600))),
			expectedError: false,
		},
		{
			name:          "success_unquoted_time_string",
			input:         []byte(`2023-01-01T12:00:00.123456Z`),
			expectedTime:  IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.UTC)),
			expectedError: false,
		},
		{
			name:          "success_leap_year_date",
			input:         []byte(`"2024-02-29T12:00:00.123456Z"`),
			expectedTime:  IdsecRFC3339Time(time.Date(2024, 2, 29, 12, 0, 0, 123456000, time.UTC)),
			expectedError: false,
		},
		{
			name:          "success_end_of_year",
			input:         []byte(`"2023-12-31T23:59:59.999999Z"`),
			expectedTime:  IdsecRFC3339Time(time.Date(2023, 12, 31, 23, 59, 59, 999999000, time.UTC)),
			expectedError: false,
		},
		{
			name:             "error_invalid_date_format",
			input:            []byte(`"2023-01-01 12:00:00"`),
			expectedError:    true,
			expectedErrorMsg: `parsing time "2023-01-01 12:00:00" as "2006-01-02T15:04:05.999999Z07:00": cannot parse " 12:00:00" as "T"`,
		},
		{
			name:             "error_invalid_month",
			input:            []byte(`"2023-13-01T12:00:00.123456Z"`),
			expectedError:    true,
			expectedErrorMsg: `parsing time "2023-13-01T12:00:00.123456Z": month out of range`,
		},
		{
			name:             "error_invalid_day",
			input:            []byte(`"2023-02-30T12:00:00.123456Z"`),
			expectedError:    true,
			expectedErrorMsg: `parsing time "2023-02-30T12:00:00.123456Z": day out of range`,
		},
		{
			name:             "error_missing_timezone",
			input:            []byte(`"2023-01-01T12:00:00.123456"`),
			expectedError:    true,
			expectedErrorMsg: `parsing time "2023-01-01T12:00:00.123456" as "2006-01-02T15:04:05.999999Z07:00": cannot parse "" as "Z07:00"`,
		},
		{
			name:             "error_empty_string",
			input:            []byte(`""`),
			expectedError:    true,
			expectedErrorMsg: `parsing time "" as "2006-01-02T15:04:05.999999Z07:00": cannot parse "" as "2006"`,
		},
		{
			name:             "error_invalid_json",
			input:            []byte(`invalid`),
			expectedError:    true,
			expectedErrorMsg: `parsing time "invalid" as "2006-01-02T15:04:05.999999Z07:00": cannot parse "invalid" as "2006"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var idsecTime IdsecRFC3339Time
			err := idsecTime.UnmarshalJSON(tt.input)

			// Validate error expectation
			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && err.Error() != tt.expectedErrorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			// Validate no error when success expected
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Validate result
			expectedTimeValue := time.Time(tt.expectedTime)
			actualTimeValue := time.Time(idsecTime)
			if !expectedTimeValue.Equal(actualTimeValue) {
				t.Errorf("Expected time %v, got %v", expectedTimeValue, actualTimeValue)
			}
		})
	}
}

func TestIdsecRFC3339Time_MarshalJSON(t *testing.T) {
	tests := []struct {
		name           string
		idsecTime      IdsecRFC3339Time
		expectedOutput []byte
		expectedError  bool
	}{
		{
			name:           "success_utc_time_with_microseconds",
			idsecTime:      IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.UTC)),
			expectedOutput: []byte(`"2023-01-01T12:00:00.123456Z"`),
			expectedError:  false,
		},
		{
			name:           "success_utc_time_without_microseconds",
			idsecTime:      IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
			expectedOutput: []byte(`"2023-01-01T12:00:00Z"`),
			expectedError:  false,
		},
		{
			name:           "success_time_with_positive_timezone",
			idsecTime:      IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.FixedZone("", 5*3600))),
			expectedOutput: []byte(`"2023-01-01T12:00:00.123456+05:00"`),
			expectedError:  false,
		},
		{
			name:           "success_time_with_negative_timezone",
			idsecTime:      IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.FixedZone("", -7*3600))),
			expectedOutput: []byte(`"2023-01-01T12:00:00.123456-07:00"`),
			expectedError:  false,
		},
		{
			name:           "success_leap_year_date",
			idsecTime:      IdsecRFC3339Time(time.Date(2024, 2, 29, 12, 0, 0, 123456000, time.UTC)),
			expectedOutput: []byte(`"2024-02-29T12:00:00.123456Z"`),
			expectedError:  false,
		},
		{
			name:           "success_end_of_year",
			idsecTime:      IdsecRFC3339Time(time.Date(2023, 12, 31, 23, 59, 59, 999999000, time.UTC)),
			expectedOutput: []byte(`"2023-12-31T23:59:59.999999Z"`),
			expectedError:  false,
		},
		{
			name:           "success_zero_time",
			idsecTime:      IdsecRFC3339Time(time.Time{}),
			expectedOutput: []byte(`"0001-01-01T00:00:00Z"`),
			expectedError:  false,
		},
		{
			name:           "success_unix_epoch",
			idsecTime:      IdsecRFC3339Time(time.Unix(0, 0).UTC()),
			expectedOutput: []byte(`"1970-01-01T00:00:00Z"`),
			expectedError:  false,
		},
		{
			name:           "success_far_future_date",
			idsecTime:      IdsecRFC3339Time(time.Date(2099, 12, 31, 23, 59, 59, 999999000, time.UTC)),
			expectedOutput: []byte(`"2099-12-31T23:59:59.999999Z"`),
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := tt.idsecTime.MarshalJSON()

			// Validate error expectation
			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			// Validate no error when success expected
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			// Validate result
			if !reflect.DeepEqual(result, tt.expectedOutput) {
				t.Errorf("Expected output %s, got %s", string(tt.expectedOutput), string(result))
			}
		})
	}
}

func TestIdsecRFC3339Time_RoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		originalTime IdsecRFC3339Time
	}{
		{
			name:         "round_trip_utc_time",
			originalTime: IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.UTC)),
		},
		{
			name:         "round_trip_timezone_offset",
			originalTime: IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.FixedZone("", 5*3600))),
		},
		{
			name:         "round_trip_negative_timezone",
			originalTime: IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.FixedZone("", -7*3600))),
		},
		{
			name:         "round_trip_zero_microseconds",
			originalTime: IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)),
		},
		{
			name:         "round_trip_maximum_microseconds",
			originalTime: IdsecRFC3339Time(time.Date(2023, 1, 1, 12, 0, 0, 999999000, time.UTC)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Marshal to JSON
			jsonData, err := tt.originalTime.MarshalJSON()
			if err != nil {
				t.Errorf("Failed to marshal time: %v", err)
				return
			}

			// Unmarshal back to IdsecRFC3339Time
			var roundTripTime IdsecRFC3339Time
			err = roundTripTime.UnmarshalJSON(jsonData)
			if err != nil {
				t.Errorf("Failed to unmarshal time: %v", err)
				return
			}

			// Compare times - they should be equal
			originalTimeValue := time.Time(tt.originalTime)
			roundTripTimeValue := time.Time(roundTripTime)
			if !originalTimeValue.Equal(roundTripTimeValue) {
				t.Errorf("Round trip failed: original %v, round trip %v", originalTimeValue, roundTripTimeValue)
			}
		})
	}
}

func TestIdsecRFC3339Time_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func() ([]byte, IdsecRFC3339Time)
		expectedError bool
		validateFunc  func(t *testing.T, idsecTime IdsecRFC3339Time, jsonData []byte)
	}{
		{
			name: "edge_case_single_quotes",
			setupFunc: func() ([]byte, IdsecRFC3339Time) {
				return []byte(`'2023-01-01T12:00:00.123456Z'`), IdsecRFC3339Time{}
			},
			expectedError: true,
		},
		{
			name: "success_partial_microseconds",
			setupFunc: func() ([]byte, IdsecRFC3339Time) {
				return []byte(`"2023-01-01T12:00:00.123Z"`), IdsecRFC3339Time{}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, idsecTime IdsecRFC3339Time, jsonData []byte) {
				expectedTime := time.Date(2023, 1, 1, 12, 0, 0, 123000000, time.UTC)
				actualTime := time.Time(idsecTime)
				if !expectedTime.Equal(actualTime) {
					t.Errorf("Expected time %v, got %v", expectedTime, actualTime)
				}
			},
		},
		{
			name: "error_missing_timezone_indicator",
			setupFunc: func() ([]byte, IdsecRFC3339Time) {
				return []byte(`"2023-01-01T12:00:00.123456"`), IdsecRFC3339Time{}
			},
			expectedError: true,
		},
		{
			name: "edge_case_no_quotes_valid_format",
			setupFunc: func() ([]byte, IdsecRFC3339Time) {
				return []byte(`2023-01-01T12:00:00.123456Z`), IdsecRFC3339Time{}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, idsecTime IdsecRFC3339Time, jsonData []byte) {
				expectedTime := time.Date(2023, 1, 1, 12, 0, 0, 123456000, time.UTC)
				actualTime := time.Time(idsecTime)
				if !expectedTime.Equal(actualTime) {
					t.Errorf("Expected time %v, got %v", expectedTime, actualTime)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			jsonData, idsecTime := tt.setupFunc()
			err := idsecTime.UnmarshalJSON(jsonData)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, idsecTime, jsonData)
			}
		})
	}
}
