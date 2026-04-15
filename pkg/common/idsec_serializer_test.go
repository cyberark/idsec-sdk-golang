package common

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

// TestStruct represents a test structure for schema-aware testing
type TestStruct struct {
	FirstName string                 `json:"first_name"`
	LastName  string                 `json:"last_name"`
	Age       int                    `json:"age"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// EmbeddedStruct represents a test structure with embedded fields
type EmbeddedStruct struct {
	TestStruct `mapstructure:",squash"`
	Email      string `json:"email"`
}

func TestSerializeResponseToJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "success_valid_json_object",
			input:    `{"name": "John", "age": 30}`,
			expected: `{"age":30,"name":"John"}`,
		},
		{
			name:     "success_valid_json_array",
			input:    `[1, 2, 3]`,
			expected: `[1, 2, 3]`,
		},
		{
			name:     "error_invalid_json",
			input:    `{invalid json}`,
			expected: `{invalid json}`,
		},
		{
			name:     "success_empty_string",
			input:    ``,
			expected: ``,
		},
		{
			name:     "success_plain_text",
			input:    `plain text response`,
			expected: `plain text response`,
		},
		{
			name:     "success_json_string",
			input:    `"hello world"`,
			expected: `"hello world"`,
		},
		{
			name:     "success_json_number",
			input:    `42`,
			expected: `42`,
		},
		{
			name:     "success_json_boolean",
			input:    `true`,
			expected: `true`,
		},
		{
			name:     "success_json_null",
			input:    `null`,
			expected: `null`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := io.NopCloser(strings.NewReader(tt.input))
			result := SerializeResponseToJSON(response)
			if result != tt.expected {
				t.Errorf("SerializeResponseToJSON() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConvertToSnakeCase(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		schema   *reflect.Type
		expected interface{}
	}{
		{
			name: "simple_map_with_camel_case_keys",
			input: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"userAge":   30,
			},
			schema: nil,
			expected: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
				"user_age":   30,
			},
		},
		{
			name: "nested_map",
			input: map[string]interface{}{
				"userInfo": map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
				},
				"accountDetails": map[string]interface{}{
					"accountId": "123",
					"isActive":  true,
				},
			},
			schema: nil,
			expected: map[string]interface{}{
				"user_info": map[string]interface{}{
					"first_name": "John",
					"last_name":  "Doe",
				},
				"account_details": map[string]interface{}{
					"account_id": "123",
					"is_active":  true,
				},
			},
		},
		{
			name: "array_of_maps",
			input: []interface{}{
				map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
				},
				map[string]interface{}{
					"firstName": "Jane",
					"lastName":  "Smith",
				},
			},
			schema: nil,
			expected: []interface{}{
				map[string]interface{}{
					"first_name": "John",
					"last_name":  "Doe",
				},
				map[string]interface{}{
					"first_name": "Jane",
					"last_name":  "Smith",
				},
			},
		},
		{
			name:     "primitive_types_unchanged",
			input:    "hello world",
			schema:   nil,
			expected: "hello world",
		},
		{
			name:     "number_unchanged",
			input:    42,
			schema:   nil,
			expected: 42,
		},
		{
			name:     "boolean_unchanged",
			input:    true,
			schema:   nil,
			expected: true,
		},
		{
			name:     "nil_input",
			input:    nil,
			schema:   nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertToSnakeCase(tt.input, tt.schema)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ConvertToSnakeCase() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConvertToCamelCase(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		schema   *reflect.Type
		expected interface{}
	}{
		{
			name: "simple_map_with_snake_case_keys",
			input: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
				"user_age":   30,
			},
			schema: nil,
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"userAge":   30,
			},
		},
		{
			name: "nested_map",
			input: map[string]interface{}{
				"user_info": map[string]interface{}{
					"first_name": "John",
					"last_name":  "Doe",
				},
				"account_details": map[string]interface{}{
					"account_id": "123",
					"is_active":  true,
				},
			},
			schema: nil,
			expected: map[string]interface{}{
				"userInfo": map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
				},
				"accountDetails": map[string]interface{}{
					"accountId": "123",
					"isActive":  true,
				},
			},
		},
		{
			name: "array_of_maps",
			input: []interface{}{
				map[string]interface{}{
					"first_name": "John",
					"last_name":  "Doe",
				},
				map[string]interface{}{
					"first_name": "Jane",
					"last_name":  "Smith",
				},
			},
			schema: nil,
			expected: []interface{}{
				map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
				},
				map[string]interface{}{
					"firstName": "Jane",
					"lastName":  "Smith",
				},
			},
		},
		{
			name:     "primitive_types_unchanged",
			input:    "hello world",
			schema:   nil,
			expected: "hello world",
		},
		{
			name:     "number_unchanged",
			input:    42,
			schema:   nil,
			expected: 42,
		},
		{
			name:     "boolean_unchanged",
			input:    true,
			schema:   nil,
			expected: true,
		},
		{
			name:     "nil_input",
			input:    nil,
			schema:   nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertToCamelCase(tt.input, tt.schema)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ConvertToCamelCase() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDeserializeJSONSnake(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    interface{}
		expectError bool
	}{
		{
			name:  "simple_json_object_with_camel_case_keys",
			input: `{"firstName": "John", "lastName": "Doe", "userAge": 30}`,
			expected: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
				"user_age":   float64(30), // JSON numbers are float64
			},
			expectError: false,
		},
		{
			name:  "nested_json_object",
			input: `{"userInfo": {"firstName": "John", "lastName": "Doe"}, "isActive": true}`,
			expected: map[string]interface{}{
				"user_info": map[string]interface{}{
					"first_name": "John",
					"last_name":  "Doe",
				},
				"is_active": true,
			},
			expectError: false,
		},
		{
			name:  "json_array",
			input: `[{"firstName": "John"}, {"firstName": "Jane"}]`,
			expected: []interface{}{
				map[string]interface{}{
					"first_name": "John",
				},
				map[string]interface{}{
					"first_name": "Jane",
				},
			},
			expectError: false,
		},
		{
			name:        "invalid_json",
			input:       `{invalid json}`,
			expected:    nil,
			expectError: true,
		},
		{
			name:        "empty_json",
			input:       `{}`,
			expected:    map[string]interface{}{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := io.NopCloser(strings.NewReader(tt.input))
			result, err := DeserializeJSONSnake(response)

			if tt.expectError {
				if err == nil {
					t.Errorf("DeserializeJSONSnake() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("DeserializeJSONSnake() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DeserializeJSONSnake() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDeserializeJSONCamel(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    interface{}
		expectError bool
	}{
		{
			name:  "simple_json_object_with_snake_case_keys",
			input: `{"first_name": "John", "last_name": "Doe", "user_age": 30}`,
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"userAge":   float64(30), // JSON numbers are float64
			},
			expectError: false,
		},
		{
			name:  "nested_json_object",
			input: `{"user_info": {"first_name": "John", "last_name": "Doe"}, "is_active": true}`,
			expected: map[string]interface{}{
				"userInfo": map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
				},
				"isActive": true,
			},
			expectError: false,
		},
		{
			name:  "json_array",
			input: `[{"first_name": "John"}, {"first_name": "Jane"}]`,
			expected: []interface{}{
				map[string]interface{}{
					"firstName": "John",
				},
				map[string]interface{}{
					"firstName": "Jane",
				},
			},
			expectError: false,
		},
		{
			name:        "invalid_json",
			input:       `{invalid json}`,
			expected:    nil,
			expectError: true,
		},
		{
			name:        "empty_json",
			input:       `{}`,
			expected:    map[string]interface{}{},
			expectError: false,
		},
		{
			name:  "mixed_keys_with_already_camel_case",
			input: `{"firstName": "John", "last_name": "Doe"}`,
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
			},
			expectError: false,
		},
		{
			name:  "deeply_nested_structure",
			input: `{"user_data": {"personal_info": {"first_name": "John", "last_name": "Doe"}, "account_status": "active"}}`,
			expected: map[string]interface{}{
				"userData": map[string]interface{}{
					"personalInfo": map[string]interface{}{
						"firstName": "John",
						"lastName":  "Doe",
					},
					"accountStatus": "active",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := io.NopCloser(strings.NewReader(tt.input))
			result, err := DeserializeJSONCamel(response)

			if tt.expectError {
				if err == nil {
					t.Errorf("DeserializeJSONCamel() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("DeserializeJSONCamel() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DeserializeJSONCamel() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSerializeJSONCamel(t *testing.T) {
	tests := []struct {
		name        string
		input       interface{}
		expected    map[string]interface{}
		expectError bool
	}{
		{
			name: "simple_struct",
			input: TestStruct{
				FirstName: "John",
				LastName:  "Doe",
				Age:       30,
				Metadata: map[string]interface{}{
					"key1": "value1",
				},
			},
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"age":       float64(30),
				"metadata": map[string]interface{}{
					"key1": "value1",
				},
			},
			expectError: false,
		},
		{
			name: "map_with_snake_case_keys",
			input: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
				"user_age":   30,
			},
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"userAge":   float64(30),
			},
			expectError: false,
		},
		{
			name: "map_with_camel_case_keys",
			input: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"userAge":   30,
			},
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"userAge":   float64(30),
			},
			expectError: false,
		},
		{
			name: "nested_structure",
			input: map[string]interface{}{
				"user_info": map[string]interface{}{
					"first_name": "John",
					"last_name":  "Doe",
				},
				"account_status": "active",
			},
			expected: map[string]interface{}{
				"userInfo": map[string]interface{}{
					"firstName": "John",
					"lastName":  "Doe",
				},
				"accountStatus": "active",
			},
			expectError: false,
		},
		{
			name:        "invalid_input_channel",
			input:       make(chan int),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SerializeJSONCamel(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("SerializeJSONCamel() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("SerializeJSONCamel() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("SerializeJSONCamel() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDeserializeJSONSnakeSchema(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		schema      *reflect.Type
		expected    interface{}
		expectError bool
	}{
		{
			name:   "json_without_schema",
			input:  `{"firstName": "John", "lastName": "Doe"}`,
			schema: nil,
			expected: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
			},
			expectError: false,
		},
		{
			name:        "invalid_json",
			input:       `{invalid json}`,
			schema:      nil,
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := io.NopCloser(strings.NewReader(tt.input))
			result, err := DeserializeJSONSnakeSchema(response, tt.schema)

			if tt.expectError {
				if err == nil {
					t.Errorf("DeserializeJSONSnakeSchema() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("DeserializeJSONSnakeSchema() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DeserializeJSONSnakeSchema() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSerializeJSONCamelSchema(t *testing.T) {
	tests := []struct {
		name        string
		input       interface{}
		schema      *reflect.Type
		expected    map[string]interface{}
		expectError bool
	}{
		{
			name: "map_without_schema",
			input: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
			},
			schema: nil,
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
			},
			expectError: false,
		},
		{
			name: "map_with_schema",
			input: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
				"age":        30,
			},
			schema: func() *reflect.Type { t := reflect.TypeOf(TestStruct{}); return &t }(),
			expected: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"age":       float64(30),
			},
			expectError: false,
		},
		{
			name:        "invalid_input_with_schema",
			input:       make(chan int),
			schema:      func() *reflect.Type { t := reflect.TypeOf(TestStruct{}); return &t }(),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SerializeJSONCamelSchema(tt.input, tt.schema)

			if tt.expectError {
				if err == nil {
					t.Errorf("SerializeJSONCamelSchema() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("SerializeJSONCamelSchema() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("SerializeJSONCamelSchema() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestResolveFieldsSquashed(t *testing.T) {
	tests := []struct {
		name     string
		schema   reflect.Type
		expected int // expected number of fields
	}{
		{
			name:     "simple_struct",
			schema:   reflect.TypeOf(TestStruct{}),
			expected: 4, // FirstName, LastName, Age, Metadata
		},
		{
			name:     "embedded_struct",
			schema:   reflect.TypeOf(EmbeddedStruct{}),
			expected: 5, // FirstName, LastName, Age, Metadata (from embedded), Email
		},
		{
			name:     "pointer_to_struct",
			schema:   reflect.TypeOf(&TestStruct{}),
			expected: 4, // FirstName, LastName, Age, Metadata
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveFieldsSquashed(tt.schema)
			if len(result) != tt.expected {
				t.Errorf("resolveFieldsSquashed() returned %d fields, want %d", len(result), tt.expected)
			}
		})
	}
}

func TestFindFieldByName(t *testing.T) {
	tests := []struct {
		name       string
		schema     reflect.Type
		fieldName  string
		expectNil  bool
		expectName string
	}{
		{
			name:       "find_existing_field",
			schema:     reflect.TypeOf(TestStruct{}),
			fieldName:  "first_name",
			expectNil:  false,
			expectName: "FirstName",
		},
		{
			name:       "find_field_with_different_case",
			schema:     reflect.TypeOf(TestStruct{}),
			fieldName:  "firstname",
			expectNil:  false,
			expectName: "FirstName",
		},
		{
			name:      "field_not_found",
			schema:    reflect.TypeOf(TestStruct{}),
			fieldName: "nonexistent_field",
			expectNil: true,
		},
		{
			name:       "find_field_in_pointer_type",
			schema:     reflect.TypeOf(&TestStruct{}),
			fieldName:  "last_name",
			expectNil:  false,
			expectName: "LastName",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindFieldByName(tt.schema, tt.fieldName)
			if tt.expectNil {
				if result != nil {
					t.Errorf("FindFieldByName() expected nil but got %v", result)
				}
			} else {
				if result == nil {
					t.Errorf("FindFieldByName() expected field but got nil")
				} else if result.Name != tt.expectName {
					t.Errorf("FindFieldByName() expected field name %s but got %s", tt.expectName, result.Name)
				}
			}
		})
	}
}

// Test error handling for SerializeResponseToJSON
func TestSerializeResponseToJSON_ErrorHandling(t *testing.T) {
	// Test with a ReadCloser that returns an error
	errorReader := &errorReadCloser{}
	result := SerializeResponseToJSON(errorReader)
	if result != "" {
		t.Errorf("SerializeResponseToJSON() with error reader expected empty string, got %v", result)
	}
}

// errorReadCloser is a helper type that always returns an error when reading
type errorReadCloser struct{}

func (e *errorReadCloser) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func (e *errorReadCloser) Close() error {
	return nil
}

func TestConvertToPascalCase(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		schema   *reflect.Type
		expected interface{}
	}{
		{
			name: "simple_map_with_snake_case_keys",
			input: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
				"user_age":   30,
			},
			schema: nil,
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"UserAge":   30,
			},
		},
		{
			name: "simple_map_with_camel_case_keys",
			input: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"userAge":   30,
			},
			schema: nil,
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"UserAge":   30,
			},
		},
		{
			name: "nested_map",
			input: map[string]interface{}{
				"user_info": map[string]interface{}{
					"first_name": "John",
					"last_name":  "Doe",
				},
				"account_details": map[string]interface{}{
					"account_id": "123",
					"is_active":  true,
				},
			},
			schema: nil,
			expected: map[string]interface{}{
				"UserInfo": map[string]interface{}{
					"FirstName": "John",
					"LastName":  "Doe",
				},
				"AccountDetails": map[string]interface{}{
					"AccountId": "123",
					"IsActive":  true,
				},
			},
		},
		{
			name: "array_of_maps",
			input: []interface{}{
				map[string]interface{}{
					"first_name": "John",
					"last_name":  "Doe",
				},
				map[string]interface{}{
					"first_name": "Jane",
					"last_name":  "Smith",
				},
			},
			schema: nil,
			expected: []interface{}{
				map[string]interface{}{
					"FirstName": "John",
					"LastName":  "Doe",
				},
				map[string]interface{}{
					"FirstName": "Jane",
					"LastName":  "Smith",
				},
			},
		},
		{
			name:     "primitive_types_unchanged",
			input:    "hello world",
			schema:   nil,
			expected: "hello world",
		},
		{
			name:     "number_unchanged",
			input:    42,
			schema:   nil,
			expected: 42,
		},
		{
			name:     "boolean_unchanged",
			input:    true,
			schema:   nil,
			expected: true,
		},
		{
			name:     "nil_input",
			input:    nil,
			schema:   nil,
			expected: nil,
		},
		{
			name: "mixed_format_keys",
			input: map[string]interface{}{
				"firstName":  "John",
				"last_name":  "Doe",
				"UserAge":    30,
				"email-addr": "john@example.com",
			},
			schema: nil,
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"UserAge":   30,
				"EmailAddr": "john@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := ConvertToPascalCase(tt.input, tt.schema)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ConvertToPascalCase() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSerializeJSONPascal(t *testing.T) {
	tests := []struct {
		name        string
		input       interface{}
		expected    map[string]interface{}
		expectError bool
	}{
		{
			name: "simple_struct",
			input: TestStruct{
				FirstName: "John",
				LastName:  "Doe",
				Age:       30,
				Metadata: map[string]interface{}{
					"key1": "value1",
				},
			},
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"Age":       float64(30),
				"Metadata": map[string]interface{}{
					"Key1": "value1",
				},
			},
			expectError: false,
		},
		{
			name: "map_with_snake_case_keys",
			input: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
				"user_age":   30,
			},
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"UserAge":   float64(30),
			},
			expectError: false,
		},
		{
			name: "map_with_camel_case_keys",
			input: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"userAge":   30,
			},
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"UserAge":   float64(30),
			},
			expectError: false,
		},
		{
			name: "nested_structure",
			input: map[string]interface{}{
				"user_info": map[string]interface{}{
					"first_name": "John",
					"last_name":  "Doe",
				},
				"account_status": "active",
			},
			expected: map[string]interface{}{
				"UserInfo": map[string]interface{}{
					"FirstName": "John",
					"LastName":  "Doe",
				},
				"AccountStatus": "active",
			},
			expectError: false,
		},
		{
			name:        "invalid_input_channel",
			input:       make(chan int),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := SerializeJSONPascal(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("SerializeJSONPascal() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("SerializeJSONPascal() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("SerializeJSONPascal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSerializeJSONPascalSchema(t *testing.T) {
	tests := []struct {
		name        string
		input       interface{}
		schema      *reflect.Type
		expected    map[string]interface{}
		expectError bool
	}{
		{
			name: "map_without_schema",
			input: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
			},
			schema: nil,
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
			},
			expectError: false,
		},
		{
			name: "map_with_schema",
			input: map[string]interface{}{
				"first_name": "John",
				"last_name":  "Doe",
				"age":        30,
			},
			schema: func() *reflect.Type { t := reflect.TypeOf(TestStruct{}); return &t }(),
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"Age":       float64(30),
			},
			expectError: false,
		},
		{
			name:        "invalid_input_with_schema",
			input:       make(chan int),
			schema:      func() *reflect.Type { t := reflect.TypeOf(TestStruct{}); return &t }(),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := SerializeJSONPascalSchema(tt.input, tt.schema)

			if tt.expectError {
				if err == nil {
					t.Errorf("SerializeJSONPascalSchema() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("SerializeJSONPascalSchema() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("SerializeJSONPascalSchema() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDeserializeJSONPascal(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    interface{}
		expectError bool
	}{
		{
			name:  "simple_json_object_with_snake_case_keys",
			input: `{"first_name": "John", "last_name": "Doe", "user_age": 30}`,
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"UserAge":   float64(30),
			},
			expectError: false,
		},
		{
			name:  "simple_json_object_with_camel_case_keys",
			input: `{"firstName": "John", "lastName": "Doe", "userAge": 30}`,
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"UserAge":   float64(30),
			},
			expectError: false,
		},
		{
			name:  "nested_json_object",
			input: `{"user_info": {"first_name": "John", "last_name": "Doe"}, "is_active": true}`,
			expected: map[string]interface{}{
				"UserInfo": map[string]interface{}{
					"FirstName": "John",
					"LastName":  "Doe",
				},
				"IsActive": true,
			},
			expectError: false,
		},
		{
			name:  "json_array",
			input: `[{"first_name": "John"}, {"first_name": "Jane"}]`,
			expected: []interface{}{
				map[string]interface{}{
					"FirstName": "John",
				},
				map[string]interface{}{
					"FirstName": "Jane",
				},
			},
			expectError: false,
		},
		{
			name:        "invalid_json",
			input:       `{invalid json}`,
			expected:    nil,
			expectError: true,
		},
		{
			name:        "empty_json",
			input:       `{}`,
			expected:    map[string]interface{}{},
			expectError: false,
		},
		{
			name:  "mixed_format_keys",
			input: `{"firstName": "John", "last_name": "Doe", "email-addr": "john@example.com"}`,
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"EmailAddr": "john@example.com",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			response := io.NopCloser(strings.NewReader(tt.input))
			result, err := DeserializeJSONPascal(response)

			if tt.expectError {
				if err == nil {
					t.Errorf("DeserializeJSONPascal() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("DeserializeJSONPascal() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DeserializeJSONPascal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDeserializeJSONPascalSchema(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		schema      *reflect.Type
		expected    interface{}
		expectError bool
	}{
		{
			name:   "json_without_schema",
			input:  `{"first_name": "John", "last_name": "Doe"}`,
			schema: nil,
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
			},
			expectError: false,
		},
		{
			name:   "json_with_schema",
			input:  `{"first_name": "John", "last_name": "Doe", "age": 30}`,
			schema: func() *reflect.Type { t := reflect.TypeOf(TestStruct{}); return &t }(),
			expected: map[string]interface{}{
				"FirstName": "John",
				"LastName":  "Doe",
				"Age":       float64(30),
			},
			expectError: false,
		},
		{
			name:        "invalid_json",
			input:       `{invalid json}`,
			schema:      nil,
			expected:    nil,
			expectError: true,
		},
		{
			name:        "empty_json_with_schema",
			input:       `{}`,
			schema:      func() *reflect.Type { t := reflect.TypeOf(TestStruct{}); return &t }(),
			expected:    map[string]interface{}{},
			expectError: false,
		},
		{
			name:   "nested_structure_with_schema",
			input:  `{"user_info": {"first_name": "John", "last_name": "Doe"}, "account_status": "active"}`,
			schema: nil,
			expected: map[string]interface{}{
				"UserInfo": map[string]interface{}{
					"FirstName": "John",
					"LastName":  "Doe",
				},
				"AccountStatus": "active",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			response := io.NopCloser(strings.NewReader(tt.input))
			result, err := DeserializeJSONPascalSchema(response, tt.schema)

			if tt.expectError {
				if err == nil {
					t.Errorf("DeserializeJSONPascalSchema() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("DeserializeJSONPascalSchema() unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("DeserializeJSONPascalSchema() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConvertKeyToPascalCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "snake_case_to_pascal_case",
			input:    "first_name",
			expected: "FirstName",
		},
		{
			name:     "camel_case_to_pascal_case",
			input:    "firstName",
			expected: "FirstName",
		},
		{
			name:     "kebab_case_to_pascal_case",
			input:    "first-name",
			expected: "FirstName",
		},
		{
			name:     "already_pascal_case",
			input:    "FirstName",
			expected: "FirstName",
		},
		{
			name:     "single_word_lowercase",
			input:    "name",
			expected: "Name",
		},
		{
			name:     "single_word_uppercase",
			input:    "NAME",
			expected: "Name",
		},
		{
			name:     "empty_string",
			input:    "",
			expected: "",
		},
		{
			name:     "multiple_underscores",
			input:    "user_first_name",
			expected: "UserFirstName",
		},
		{
			name:     "multiple_hyphens",
			input:    "user-first-name",
			expected: "UserFirstName",
		},
		{
			name:     "mixed_separators",
			input:    "user_first-name",
			expected: "UserFirstName",
		},
		{
			name:     "with_spaces",
			input:    "first name",
			expected: "FirstName",
		},
		{
			name:     "consecutive_uppercase",
			input:    "userID",
			expected: "UserId",
		},
		{
			name:     "all_caps_with_underscores",
			input:    "USER_FIRST_NAME",
			expected: "UserFirstName",
		},
		{
			name:     "multiple_consecutive_capitals",
			input:    "HTTPS",
			expected: "Https",
		},
		{
			name:     "multiple_consecutive_capitals_with_separator",
			input:    "HTTPS_URL",
			expected: "HttpsUrl",
		},
		{
			name:     "real_world_generate_oracle_tnsnames",
			input:    "generate-oracle-tnsnames",
			expected: "GenerateOracleTnsnames",
		},
		{
			name:     "real_world_short_lived_ssh_key",
			input:    "short-lived-ssh-key",
			expected: "ShortLivedSshKey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := ConvertKeyToPascalCase(tt.input)
			if result != tt.expected {
				t.Errorf("ConvertKeyToPascalCase() = %v, want %v", result, tt.expected)
			}
		})
	}
}
