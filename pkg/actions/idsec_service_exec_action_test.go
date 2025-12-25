package actions

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/cyberark/idsec-sdk-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

// DefaultTestSchema represents a schema with various default values for testing
type DefaultTestSchema struct {
	// Basic types with defaults
	StringField  string  `default:"default_string"`
	IntField     int     `default:"42"`
	BoolField    bool    `default:"true"`
	Float64Field float64 `default:"3.14"`

	// Pointer fields with defaults
	StringPtr  *string  `default:"ptr_string"`
	IntPtr     *int     `default:"100"`
	BoolPtr    *bool    `default:"false"`
	Float32Ptr *float32 `default:"2.71"`

	// Fields without defaults
	NoDefaultString string
	NoDefaultInt    int

	// Nested struct with defaults
	NestedStruct NestedDefaultStruct

	// Pointer to nested struct with defaults
	NestedPtr *NestedDefaultStruct

	// Embedded struct with squash
	EmbeddedStruct `mapstructure:",squash"`
}

// NestedDefaultStruct represents a nested struct with defaults
type NestedDefaultStruct struct {
	NestedString string `default:"nested_default"`
	NestedInt    int    `default:"999"`
	NestedBool   bool   `default:"true"`
}

// EmbeddedStruct represents an embedded struct with squash tag
type EmbeddedStruct struct {
	EmbeddedField string `default:"embedded_value"`
	EmbeddedInt   int    `default:"777"`
}

// ComplexDefaultSchema represents a more complex schema for testing
type ComplexDefaultSchema struct {
	Level1String string                 `default:"level1"`
	Level1Int    int                    `default:"1"`
	Level2       *ComplexNestedDefaults `mapstructure:",squash"`
}

// ComplexNestedDefaults represents nested defaults for complex testing
type ComplexNestedDefaults struct {
	Level2String string `default:"level2"`
	Level2Int    int    `default:"2"`
	Level3       *ComplexNestedDefaults2
}

// ComplexNestedDefaults2 represents deeply nested defaults
type ComplexNestedDefaults2 struct {
	Level3String string `default:"level3"`
	Level3Int    int    `default:"3"`
}

// NoDefaultsSchema represents a schema without any defaults
type NoDefaultsSchema struct {
	StringField string
	IntField    int
	BoolField   bool
}

// MixedDefaultSchema represents a schema with mixed default and non-default fields
type MixedDefaultSchema struct {
	WithDefault    string `default:"has_default"`
	WithoutDefault string
	IntWithDefault int `default:"50"`
	IntNoDefault   int
}

// CreateDefaultTestSchema creates a new DefaultTestSchema instance
func CreateDefaultTestSchema() *DefaultTestSchema {
	return &DefaultTestSchema{}
}

// CreateComplexDefaultSchema creates a new ComplexDefaultSchema instance
func CreateComplexDefaultSchema() *ComplexDefaultSchema {
	return &ComplexDefaultSchema{}
}

// CreateNoDefaultsSchema creates a new NoDefaultsSchema instance
func CreateNoDefaultsSchema() *NoDefaultsSchema {
	return &NoDefaultsSchema{}
}

// CreateMixedDefaultSchema creates a new MixedDefaultSchema instance
func CreateMixedDefaultSchema() *MixedDefaultSchema {
	return &MixedDefaultSchema{}
}

// Mock service for testing method finding
type mockService struct {
	testActionFunc func(*testutils.TestSchema) (interface{}, error)
}

func (m *mockService) TestAction(schema *testutils.TestSchema) (interface{}, error) {
	if m.testActionFunc != nil {
		return m.testActionFunc(schema)
	}
	return map[string]interface{}{"result": "success", "name": schema.Name}, nil
}

func TestNewIdsecServiceExecAction(t *testing.T) {
	tests := []struct {
		name         string
		setupLoader  func() *profiles.ProfileLoader
		validateFunc func(t *testing.T, action *IdsecServiceExecAction)
	}{
		{
			name: "success_creates_action_with_profile_loader",
			setupLoader: func() *profiles.ProfileLoader {
				mock := testutils.NewMockProfileLoader()
				return mock.AsProfileLoader()
			},
			validateFunc: func(t *testing.T, action *IdsecServiceExecAction) {
				if action == nil {
					t.Error("Expected non-nil action")
				}
				if action.IdsecBaseExecAction == nil {
					t.Error("Expected non-nil IdsecBaseExecAction")
				}
			},
		},
		{
			name: "success_creates_action_with_nil_loader",
			setupLoader: func() *profiles.ProfileLoader {
				return nil
			},
			validateFunc: func(t *testing.T, action *IdsecServiceExecAction) {
				if action == nil {
					t.Error("Expected non-nil action")
				}
				if action.IdsecBaseExecAction == nil {
					t.Error("Expected non-nil IdsecBaseExecAction")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			loader := tt.setupLoader()
			action := NewIdsecServiceExecAction(loader)

			tt.validateFunc(t, action)
		})
	}
}

func TestIdsecServiceExecAction_isComplexType(t *testing.T) {
	tests := []struct {
		name     string
		field    reflect.StructField
		expected bool
	}{
		{
			name: "success_map_string_struct_is_complex",
			field: reflect.StructField{
				Type: reflect.TypeOf(map[string]testutils.TestComplexType{}),
			},
			expected: true,
		},
		{
			name: "success_slice_struct_is_complex",
			field: reflect.StructField{
				Type: reflect.TypeOf([]testutils.TestComplexType{}),
			},
			expected: true,
		},
		{
			name: "success_array_struct_is_complex",
			field: reflect.StructField{
				Type: reflect.TypeOf([5]testutils.TestComplexType{}),
			},
			expected: true,
		},
		{
			name: "success_string_is_not_complex",
			field: reflect.StructField{
				Type: reflect.TypeOf(""),
			},
			expected: false,
		},
		{
			name: "success_int_is_not_complex",
			field: reflect.StructField{
				Type: reflect.TypeOf(0),
			},
			expected: false,
		},
		{
			name: "success_slice_string_is_not_complex",
			field: reflect.StructField{
				Type: reflect.TypeOf([]string{}),
			},
			expected: false,
		},
		{
			name: "success_map_string_string_is_not_complex",
			field: reflect.StructField{
				Type: reflect.TypeOf(map[string]string{}),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			result := action.isComplexType(tt.field)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIdsecServiceExecAction_fillRemainingSchema(t *testing.T) {
	tests := []struct {
		name         string
		schema       interface{}
		validateFunc func(t *testing.T, flags *pflag.FlagSet)
	}{
		{
			name:   "success_adds_complex_type_flags",
			schema: testutils.CreateTestSchema(),
			validateFunc: func(t *testing.T, flags *pflag.FlagSet) {
				// Check that complex_data flag was added for the complex slice field
				flag := flags.Lookup("complex_data")
				if flag == nil {
					t.Error("Expected complex_data flag to be added")
				}
				if flag != nil && !strings.Contains(flag.Usage, "JSON") {
					t.Error("Expected complex type flag to have JSON hint in description")
				}
			},
		},
		{
			name:   "success_handles_empty_schema",
			schema: &struct{}{},
			validateFunc: func(t *testing.T, flags *pflag.FlagSet) {
				// Should not add any flags for empty schema
				if flags.NFlag() > 0 {
					t.Error("Expected no flags for empty schema")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)

			action.fillRemainingSchema(tt.schema, flags)

			tt.validateFunc(t, flags)
		})
	}
}

func TestIdsecServiceExecAction_fillParsedFlag(t *testing.T) {
	tests := []struct {
		name          string
		schemaElem    reflect.Type
		flags         map[string]interface{}
		key           string
		flag          *pflag.Flag
		expectedError bool
		validateFunc  func(t *testing.T, flags map[string]interface{})
	}{
		{
			name:          "success_parses_json_for_complex_slice",
			schemaElem:    reflect.TypeOf(*testutils.CreateTestSchema()),
			flags:         map[string]interface{}{"complex_data": `[{"id":"1","type":"test"}]`},
			key:           "complex_data",
			flag:          &pflag.Flag{Name: "complex-data"},
			expectedError: false,
			validateFunc: func(t *testing.T, flags map[string]interface{}) {
				value, ok := flags["complex_data"]
				if !ok {
					t.Error("Expected complex_data in flags")
					return
				}
				sliceVal, ok := value.([]map[string]interface{})
				if !ok {
					t.Errorf("Expected []map[string]interface{}, got %T", value)
					return
				}
				if len(sliceVal) != 1 {
					t.Errorf("Expected 1 element, got %d", len(sliceVal))
				}
			},
		},
		{
			name:          "error_invalid_json_for_complex_type",
			schemaElem:    reflect.TypeOf(*testutils.CreateTestSchema()),
			flags:         map[string]interface{}{"complex_data": `invalid json`},
			key:           "complex_data",
			flag:          &pflag.Flag{Name: "complex-data"},
			expectedError: true,
		},
		{
			name:          "error_invalid_choice_value",
			schemaElem:    reflect.TypeOf(*testutils.CreateTestSchema()),
			flags:         map[string]interface{}{"choices": "invalid_choice"},
			key:           "choices",
			flag:          &pflag.Flag{Name: "choices"},
			expectedError: true,
		},
		{
			name:          "success_valid_choice_value",
			schemaElem:    reflect.TypeOf(*testutils.CreateTestSchema()),
			flags:         map[string]interface{}{"choices": "option1"},
			key:           "choices",
			flag:          &pflag.Flag{Name: "choices"},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			err := action.fillParsedFlag(tt.schemaElem, tt.flags, tt.key, tt.flag)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if !tt.expectedError && tt.validateFunc != nil {
				tt.validateFunc(t, tt.flags)
			}
		})
	}
}

func TestIdsecServiceExecAction_parseFlag(t *testing.T) {
	tests := []struct {
		name          string
		setupCmd      func() *cobra.Command
		setupFlag     func(*cobra.Command) *pflag.Flag
		schema        interface{}
		expectedError bool
		validateFunc  func(t *testing.T, flags map[string]interface{})
	}{
		{
			name: "success_parses_string_flag",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("test-flag", "default", "test flag")
				return cmd
			},
			setupFlag: func(cmd *cobra.Command) *pflag.Flag {
				flag := cmd.Flags().Lookup("test-flag")
				flag.Value.Set("test-value")
				flag.Changed = true
				return flag
			},
			schema:        testutils.CreateTestSchema(),
			expectedError: false,
			validateFunc: func(t *testing.T, flags map[string]interface{}) {
				if flags["test_flag"] != "test-value" {
					t.Errorf("Expected test-value, got %v", flags["test_flag"])
				}
			},
		},
		{
			name: "success_parses_int_flag",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().Int("count", 0, "count flag")
				return cmd
			},
			setupFlag: func(cmd *cobra.Command) *pflag.Flag {
				flag := cmd.Flags().Lookup("count")
				flag.Value.Set("42")
				flag.Changed = true
				return flag
			},
			schema:        testutils.CreateTestSchema(),
			expectedError: false,
			validateFunc: func(t *testing.T, flags map[string]interface{}) {
				if flags["count"] != 42 {
					t.Errorf("Expected 42, got %v", flags["count"])
				}
			},
		},
		{
			name: "success_skips_unchanged_flag",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("unchanged", "default", "unchanged flag")
				return cmd
			},
			setupFlag: func(cmd *cobra.Command) *pflag.Flag {
				flag := cmd.Flags().Lookup("unchanged")
				flag.Changed = false // Not changed
				return flag
			},
			schema:        testutils.CreateTestSchema(),
			expectedError: false,
			validateFunc: func(t *testing.T, flags map[string]interface{}) {
				if _, exists := flags["unchanged"]; exists {
					t.Error("Expected unchanged flag to be skipped")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			cmd := tt.setupCmd()
			flag := tt.setupFlag(cmd)
			flags := make(map[string]interface{})

			err := action.parseFlag(flag, cmd, flags, tt.schema)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if !tt.expectedError && tt.validateFunc != nil {
				tt.validateFunc(t, flags)
			}
		})
	}
}

func TestIdsecServiceExecAction_findMethodByName(t *testing.T) {
	tests := []struct {
		name          string
		value         reflect.Value
		methodName    string
		expectedError bool
		expectedFound bool
	}{
		{
			name:          "success_finds_exact_match",
			value:         reflect.ValueOf(&mockService{}),
			methodName:    "TestAction",
			expectedError: false,
			expectedFound: true,
		},
		{
			name:          "success_finds_case_insensitive_match",
			value:         reflect.ValueOf(&mockService{}),
			methodName:    "testaction",
			expectedError: false,
			expectedFound: true,
		},
		{
			name:          "error_method_not_found",
			value:         reflect.ValueOf(&mockService{}),
			methodName:    "NonExistentMethod",
			expectedError: true,
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			method, err := action.findMethodByName(tt.value, tt.methodName)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if tt.expectedFound && (method == nil || !method.IsValid()) {
				t.Error("Expected to find method, but didn't")
			}
			if !tt.expectedFound && method != nil && method.IsValid() {
				t.Error("Expected not to find method, but did")
			}
		})
	}
}

func TestIdsecServiceExecAction_DefineExecAction(t *testing.T) {
	tests := []struct {
		name          string
		setupCmd      func() *cobra.Command
		expectedError bool
		validateFunc  func(t *testing.T, cmd *cobra.Command)
	}{
		{
			name: "success_defines_actions_without_error",
			setupCmd: func() *cobra.Command {
				return &cobra.Command{Use: "test"}
			},
			expectedError: false,
			validateFunc: func(t *testing.T, cmd *cobra.Command) {
				// Check that subcommands were added (depending on services.SupportedServiceActions)
				if cmd.Commands() == nil {
					// This may be expected if no supported service actions are defined
					t.Log("No commands added - this may be expected if services.SupportedServiceActions is empty")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			cmd := tt.setupCmd()

			err := action.DefineExecAction(cmd)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if !tt.expectedError && tt.validateFunc != nil {
				tt.validateFunc(t, cmd)
			}
		})
	}
}

func TestIdsecServiceExecAction_serializeAndPrintOutput(t *testing.T) {
	tests := []struct {
		name       string
		result     []reflect.Value
		actionName string
		// Note: This function prints to console, so we mainly test that it doesn't panic
		shouldPanic bool
	}{
		{
			name: "success_handles_struct_output",
			result: []reflect.Value{
				reflect.ValueOf(map[string]interface{}{"key": "value"}),
			},
			actionName:  "test-action",
			shouldPanic: false,
		},
		{
			name: "success_handles_int_output",
			result: []reflect.Value{
				reflect.ValueOf(42),
			},
			actionName:  "test-action",
			shouldPanic: false,
		},
		{
			name: "success_handles_string_output",
			result: []reflect.Value{
				reflect.ValueOf("test result"),
			},
			actionName:  "test-action",
			shouldPanic: false,
		},
		{
			name:        "success_handles_empty_result",
			result:      []reflect.Value{},
			actionName:  "test-action",
			shouldPanic: false,
		},
		{
			name: "success_handles_nil_pointer",
			result: []reflect.Value{
				reflect.ValueOf((*string)(nil)),
			},
			actionName:  "test-action",
			shouldPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)

			defer func() {
				if r := recover(); r != nil && !tt.shouldPanic {
					t.Errorf("Function panicked unexpectedly: %v", r)
				} else if r == nil && tt.shouldPanic {
					t.Error("Expected function to panic, but it didn't")
				}
			}()

			action.serializeAndPrintOutput(tt.result, tt.actionName)
		})
	}
}

func TestIdsecServiceExecAction_defineServiceExecAction(t *testing.T) {
	tests := []struct {
		name             string
		actionDef        *actions.IdsecServiceCLIActionDefinition
		parentActionsDef []*actions.IdsecServiceCLIActionDefinition
		expectedError    bool
		validateFunc     func(t *testing.T, cmd *cobra.Command, err error)
	}{
		{
			name: "success_creates_simple_action",
			actionDef: &actions.IdsecServiceCLIActionDefinition{
				IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
					ActionName: "test-action",
					Schemas: map[string]interface{}{
						"execute": testutils.CreateTestSchema(),
					},
				},
			},
			parentActionsDef: nil,
			expectedError:    false,
			validateFunc: func(t *testing.T, cmd *cobra.Command, err error) {
				if cmd == nil {
					t.Error("Expected command to be created")
					return
				}
				if cmd.Use != "test-action" {
					t.Errorf("Expected command name 'test-action', got '%s'", cmd.Use)
				}
			},
		},
		{
			name: "success_creates_action_with_parent",
			actionDef: &actions.IdsecServiceCLIActionDefinition{
				IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
					ActionName: "sub-action",
					Schemas:    map[string]interface{}{"execute": testutils.CreateTestSchema()},
				},
			},
			parentActionsDef: []*actions.IdsecServiceCLIActionDefinition{
				{
					IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
						ActionName: "parent-action",
					},
				},
			},
			expectedError: false,
			validateFunc: func(t *testing.T, cmd *cobra.Command, err error) {
				if cmd == nil {
					t.Error("Expected command to be created")
					return
				}
				if cmd.Use != "sub-action" {
					t.Errorf("Expected command name 'sub-action', got '%s'", cmd.Use)
				}
			},
		},
		{
			name: "success_creates_action_without_schemas",
			actionDef: &actions.IdsecServiceCLIActionDefinition{
				IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
					ActionName: "no-schema-action",
					Schemas:    map[string]interface{}{},
				},
			},
			parentActionsDef: nil,
			expectedError:    false,
			validateFunc: func(t *testing.T, cmd *cobra.Command, err error) {
				if cmd == nil {
					t.Error("Expected command to be created")
					return
				}
				if len(cmd.Commands()) != 0 {
					t.Error("Expected no subcommands for action without schemas")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			parentCmd := &cobra.Command{Use: "parent"}

			resultCmd, err := action.defineServiceExecAction(tt.actionDef, parentCmd, tt.parentActionsDef)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, resultCmd, err)
			}
		})
	}
}

// Helper function to create a test action definition
func createTestActionDefinition(name string, hasSubactions bool) *actions.IdsecServiceCLIActionDefinition {
	actionDef := &actions.IdsecServiceCLIActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName: name,
			Schemas: map[string]interface{}{
				"execute": testutils.CreateTestSchema(),
			},
		},
	}

	if hasSubactions {
		actionDef.Subactions = []*actions.IdsecServiceCLIActionDefinition{
			{
				IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
					ActionName: "sub-" + name,
					Schemas: map[string]interface{}{
						"sub-execute": testutils.CreateTestSchema(),
					},
				},
			},
		}
	}

	return actionDef
}

func TestIdsecServiceExecAction_defineServiceExecActions(t *testing.T) {
	tests := []struct {
		name             string
		actionDef        *actions.IdsecServiceCLIActionDefinition
		parentActionsDef []*actions.IdsecServiceCLIActionDefinition
		expectedError    bool
		validateFunc     func(t *testing.T, cmd *cobra.Command, err error)
	}{
		{
			name:             "success_defines_action_without_subactions",
			actionDef:        createTestActionDefinition("simple", false),
			parentActionsDef: nil,
			expectedError:    false,
			validateFunc: func(t *testing.T, cmd *cobra.Command, err error) {
				if len(cmd.Commands()) == 0 {
					t.Error("Expected at least one command to be added")
				}
			},
		},
		{
			name:             "success_defines_action_with_subactions",
			actionDef:        createTestActionDefinition("complex", true),
			parentActionsDef: nil,
			expectedError:    false,
			validateFunc: func(t *testing.T, cmd *cobra.Command, err error) {
				if len(cmd.Commands()) == 0 {
					t.Error("Expected at least one command to be added")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			cmd := &cobra.Command{Use: "parent"}

			err := action.defineServiceExecActions(tt.actionDef, cmd, tt.parentActionsDef)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, cmd, err)
			}
		})
	}
}

func TestIdsecServiceExecAction_isZeroValue(t *testing.T) {
	tests := []struct {
		name     string
		value    reflect.Value
		expected bool
	}{
		{
			name:     "success_zero_string_is_zero",
			value:    reflect.ValueOf(""),
			expected: true,
		},
		{
			name:     "success_non_zero_string_is_not_zero",
			value:    reflect.ValueOf("test"),
			expected: false,
		},
		{
			name:     "success_zero_int_is_zero",
			value:    reflect.ValueOf(0),
			expected: true,
		},
		{
			name:     "success_non_zero_int_is_not_zero",
			value:    reflect.ValueOf(42),
			expected: false,
		},
		{
			name:     "success_false_bool_is_zero",
			value:    reflect.ValueOf(false),
			expected: true,
		},
		{
			name:     "success_true_bool_is_not_zero",
			value:    reflect.ValueOf(true),
			expected: false,
		},
		{
			name:     "success_nil_pointer_is_zero",
			value:    reflect.ValueOf((*string)(nil)),
			expected: true,
		},
		{
			name:     "success_non_nil_pointer_is_not_zero",
			value:    reflect.ValueOf(common.Ptr("test")),
			expected: false,
		},
		{
			name:     "success_zero_float_is_zero",
			value:    reflect.ValueOf(0.0),
			expected: true,
		},
		{
			name:     "success_non_zero_float_is_not_zero",
			value:    reflect.ValueOf(3.14),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			result := action.isZeroValue(tt.value)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIdsecServiceExecAction_setFromString(t *testing.T) {
	tests := []struct {
		name          string
		setupValue    func() reflect.Value
		str           string
		expectedError bool
		validateFunc  func(t *testing.T, value reflect.Value)
	}{
		{
			name: "success_set_string",
			setupValue: func() reflect.Value {
				var s string
				return reflect.ValueOf(&s).Elem()
			},
			str:           "test_string",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.String() != "test_string" {
					t.Errorf("Expected 'test_string', got '%s'", value.String())
				}
			},
		},
		{
			name: "success_set_bool_true",
			setupValue: func() reflect.Value {
				var b bool
				return reflect.ValueOf(&b).Elem()
			},
			str:           "true",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if !value.Bool() {
					t.Error("Expected true, got false")
				}
			},
		},
		{
			name: "success_set_bool_false",
			setupValue: func() reflect.Value {
				var b bool
				return reflect.ValueOf(&b).Elem()
			},
			str:           "false",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.Bool() {
					t.Error("Expected false, got true")
				}
			},
		},
		{
			name: "error_invalid_bool",
			setupValue: func() reflect.Value {
				var b bool
				return reflect.ValueOf(&b).Elem()
			},
			str:           "invalid",
			expectedError: true,
		},
		{
			name: "success_set_int",
			setupValue: func() reflect.Value {
				var i int
				return reflect.ValueOf(&i).Elem()
			},
			str:           "42",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.Int() != 42 {
					t.Errorf("Expected 42, got %d", value.Int())
				}
			},
		},
		{
			name: "success_set_negative_int",
			setupValue: func() reflect.Value {
				var i int
				return reflect.ValueOf(&i).Elem()
			},
			str:           "-100",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.Int() != -100 {
					t.Errorf("Expected -100, got %d", value.Int())
				}
			},
		},
		{
			name: "error_invalid_int",
			setupValue: func() reflect.Value {
				var i int
				return reflect.ValueOf(&i).Elem()
			},
			str:           "not_a_number",
			expectedError: true,
		},
		{
			name: "success_set_int64",
			setupValue: func() reflect.Value {
				var i int64
				return reflect.ValueOf(&i).Elem()
			},
			str:           "9223372036854775807",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.Int() != 9223372036854775807 {
					t.Errorf("Expected max int64, got %d", value.Int())
				}
			},
		},
		{
			name: "success_set_uint",
			setupValue: func() reflect.Value {
				var i uint
				return reflect.ValueOf(&i).Elem()
			},
			str:           "42",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.Uint() != 42 {
					t.Errorf("Expected 42, got %d", value.Uint())
				}
			},
		},
		{
			name: "error_negative_uint",
			setupValue: func() reflect.Value {
				var i uint
				return reflect.ValueOf(&i).Elem()
			},
			str:           "-1",
			expectedError: true,
		},
		{
			name: "success_set_float32",
			setupValue: func() reflect.Value {
				var f float32
				return reflect.ValueOf(&f).Elem()
			},
			str:           "3.14",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.Float() < 3.13 || value.Float() > 3.15 {
					t.Errorf("Expected ~3.14, got %f", value.Float())
				}
			},
		},
		{
			name: "success_set_float64",
			setupValue: func() reflect.Value {
				var f float64
				return reflect.ValueOf(&f).Elem()
			},
			str:           "2.718281828",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.Float() < 2.718 || value.Float() > 2.719 {
					t.Errorf("Expected ~2.718, got %f", value.Float())
				}
			},
		},
		{
			name: "error_invalid_float",
			setupValue: func() reflect.Value {
				var f float64
				return reflect.ValueOf(&f).Elem()
			},
			str:           "not_a_float",
			expectedError: true,
		},
		{
			name: "success_set_pointer_string",
			setupValue: func() reflect.Value {
				var s *string
				return reflect.ValueOf(&s).Elem()
			},
			str:           "pointer_value",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.IsNil() {
					t.Error("Expected non-nil pointer")
					return
				}
				if value.Elem().String() != "pointer_value" {
					t.Errorf("Expected 'pointer_value', got '%s'", value.Elem().String())
				}
			},
		},
		{
			name: "success_set_pointer_int",
			setupValue: func() reflect.Value {
				var i *int
				return reflect.ValueOf(&i).Elem()
			},
			str:           "999",
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.IsNil() {
					t.Error("Expected non-nil pointer")
					return
				}
				if value.Elem().Int() != 999 {
					t.Errorf("Expected 999, got %d", value.Elem().Int())
				}
			},
		},
		{
			name: "error_unsupported_type",
			setupValue: func() reflect.Value {
				var m map[string]string
				return reflect.ValueOf(&m).Elem()
			},
			str:           "value",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			value := tt.setupValue()

			err := action.setFromString(value, tt.str)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if !tt.expectedError && tt.validateFunc != nil {
				tt.validateFunc(t, value)
			}
		})
	}
}

func TestIdsecServiceExecAction_hasInnerDefaults(t *testing.T) {
	tests := []struct {
		name     string
		typ      reflect.Type
		expected bool
	}{
		{
			name:     "success_struct_with_defaults_has_inner_defaults",
			typ:      reflect.TypeOf(DefaultTestSchema{}),
			expected: true,
		},
		{
			name:     "success_pointer_to_struct_with_defaults_has_inner_defaults",
			typ:      reflect.TypeOf(&DefaultTestSchema{}),
			expected: true,
		},
		{
			name:     "success_struct_without_defaults_no_inner_defaults",
			typ:      reflect.TypeOf(NoDefaultsSchema{}),
			expected: false,
		},
		{
			name:     "success_nested_struct_with_defaults_has_inner_defaults",
			typ:      reflect.TypeOf(ComplexDefaultSchema{}),
			expected: true,
		},
		{
			name:     "success_string_type_no_inner_defaults",
			typ:      reflect.TypeOf(""),
			expected: false,
		},
		{
			name:     "success_int_type_no_inner_defaults",
			typ:      reflect.TypeOf(0),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			result := action.hasInnerDefaults(tt.typ)

			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIdsecServiceExecAction_applyDefaults(t *testing.T) {
	tests := []struct {
		name          string
		setupTarget   func() interface{}
		expectedError bool
		validateFunc  func(t *testing.T, target interface{})
	}{
		{
			name: "success_applies_basic_defaults",
			setupTarget: func() interface{} {
				return CreateDefaultTestSchema()
			},
			expectedError: false,
			validateFunc: func(t *testing.T, target interface{}) {
				schema := target.(*DefaultTestSchema)
				if schema.StringField != "default_string" {
					t.Errorf("Expected 'default_string', got '%s'", schema.StringField)
				}
				if schema.IntField != 42 {
					t.Errorf("Expected 42, got %d", schema.IntField)
				}
				if !schema.BoolField {
					t.Error("Expected true, got false")
				}
				if schema.Float64Field < 3.13 || schema.Float64Field > 3.15 {
					t.Errorf("Expected ~3.14, got %f", schema.Float64Field)
				}
			},
		},
		{
			name: "success_applies_pointer_defaults",
			setupTarget: func() interface{} {
				return CreateDefaultTestSchema()
			},
			expectedError: false,
			validateFunc: func(t *testing.T, target interface{}) {
				schema := target.(*DefaultTestSchema)
				if schema.StringPtr == nil {
					t.Error("Expected non-nil StringPtr")
				} else if *schema.StringPtr != "ptr_string" {
					t.Errorf("Expected 'ptr_string', got '%s'", *schema.StringPtr)
				}
				if schema.IntPtr == nil {
					t.Error("Expected non-nil IntPtr")
				} else if *schema.IntPtr != 100 {
					t.Errorf("Expected 100, got %d", *schema.IntPtr)
				}
				if schema.BoolPtr == nil {
					t.Error("Expected non-nil BoolPtr")
				} else if *schema.BoolPtr {
					t.Error("Expected false, got true")
				}
			},
		},
		{
			name: "success_applies_nested_struct_defaults",
			setupTarget: func() interface{} {
				return CreateDefaultTestSchema()
			},
			expectedError: false,
			validateFunc: func(t *testing.T, target interface{}) {
				schema := target.(*DefaultTestSchema)
				if schema.NestedStruct.NestedString != "nested_default" {
					t.Errorf("Expected 'nested_default', got '%s'", schema.NestedStruct.NestedString)
				}
				if schema.NestedStruct.NestedInt != 999 {
					t.Errorf("Expected 999, got %d", schema.NestedStruct.NestedInt)
				}
				if !schema.NestedStruct.NestedBool {
					t.Error("Expected true for nested bool")
				}
			},
		},
		{
			name: "success_applies_embedded_squash_defaults",
			setupTarget: func() interface{} {
				return CreateDefaultTestSchema()
			},
			expectedError: false,
			validateFunc: func(t *testing.T, target interface{}) {
				schema := target.(*DefaultTestSchema)
				if schema.EmbeddedField != "embedded_value" {
					t.Errorf("Expected 'embedded_value', got '%s'", schema.EmbeddedField)
				}
				if schema.EmbeddedInt != 777 {
					t.Errorf("Expected 777, got %d", schema.EmbeddedInt)
				}
			},
		},
		{
			name: "success_initializes_nil_pointer_with_defaults",
			setupTarget: func() interface{} {
				return CreateDefaultTestSchema()
			},
			expectedError: false,
			validateFunc: func(t *testing.T, target interface{}) {
				schema := target.(*DefaultTestSchema)
				if schema.NestedPtr == nil {
					t.Error("Expected non-nil NestedPtr with defaults")
				} else {
					if schema.NestedPtr.NestedString != "nested_default" {
						t.Errorf("Expected 'nested_default', got '%s'", schema.NestedPtr.NestedString)
					}
				}
			},
		},
		{
			name: "success_does_not_override_user_set_values",
			setupTarget: func() interface{} {
				schema := CreateDefaultTestSchema()
				schema.StringField = "user_value"
				schema.IntField = 999
				return schema
			},
			expectedError: false,
			validateFunc: func(t *testing.T, target interface{}) {
				schema := target.(*DefaultTestSchema)
				if schema.StringField != "user_value" {
					t.Errorf("Expected 'user_value', got '%s'", schema.StringField)
				}
				if schema.IntField != 999 {
					t.Errorf("Expected 999, got %d", schema.IntField)
				}
			},
		},
		{
			name: "success_handles_complex_nested_defaults",
			setupTarget: func() interface{} {
				return CreateComplexDefaultSchema()
			},
			expectedError: false,
			validateFunc: func(t *testing.T, target interface{}) {
				schema := target.(*ComplexDefaultSchema)
				if schema.Level1String != "level1" {
					t.Errorf("Expected 'level1', got '%s'", schema.Level1String)
				}
				if schema.Level1Int != 1 {
					t.Errorf("Expected 1, got %d", schema.Level1Int)
				}
				if schema.Level2 == nil {
					t.Error("Expected non-nil Level2")
				} else {
					if schema.Level2.Level2String != "level2" {
						t.Errorf("Expected 'level2', got '%s'", schema.Level2.Level2String)
					}
					if schema.Level2.Level3 == nil {
						t.Error("Expected non-nil Level3")
					} else {
						if schema.Level2.Level3.Level3String != "level3" {
							t.Errorf("Expected 'level3', got '%s'", schema.Level2.Level3.Level3String)
						}
					}
				}
			},
		},
		{
			name: "success_no_defaults_schema_unchanged",
			setupTarget: func() interface{} {
				return CreateNoDefaultsSchema()
			},
			expectedError: false,
			validateFunc: func(t *testing.T, target interface{}) {
				schema := target.(*NoDefaultsSchema)
				if schema.StringField != "" {
					t.Errorf("Expected empty string, got '%s'", schema.StringField)
				}
				if schema.IntField != 0 {
					t.Errorf("Expected 0, got %d", schema.IntField)
				}
				if schema.BoolField {
					t.Error("Expected false, got true")
				}
			},
		},
		{
			name: "error_non_pointer_target",
			setupTarget: func() interface{} {
				schema := CreateDefaultTestSchema()
				return *schema // Return value instead of pointer
			},
			expectedError: true,
		},
		{
			name: "error_nil_pointer",
			setupTarget: func() interface{} {
				return (*DefaultTestSchema)(nil)
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			target := tt.setupTarget()

			err := action.applyDefaults(target)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if !tt.expectedError && tt.validateFunc != nil {
				tt.validateFunc(t, target)
			}
		})
	}
}

func TestIdsecServiceExecAction_applyDefaultsRec(t *testing.T) {
	tests := []struct {
		name          string
		setupValue    func() reflect.Value
		expectedError bool
		validateFunc  func(t *testing.T, value reflect.Value)
	}{
		{
			name: "success_applies_defaults_to_struct",
			setupValue: func() reflect.Value {
				schema := CreateDefaultTestSchema()
				return reflect.ValueOf(schema).Elem()
			},
			expectedError: false,
			validateFunc: func(t *testing.T, value reflect.Value) {
				if value.FieldByName("StringField").String() != "default_string" {
					t.Errorf("Expected 'default_string', got '%s'", value.FieldByName("StringField").String())
				}
			},
		},
		{
			name: "success_handles_non_struct_gracefully",
			setupValue: func() reflect.Value {
				s := "test"
				return reflect.ValueOf(&s).Elem()
			},
			expectedError: false,
		},
		{
			name: "success_handles_unexported_fields",
			setupValue: func() reflect.Value {
				type testStruct struct {
					exported   string `default:"value"`
					unexported string `default:"ignored"`
				}
				ts := &testStruct{}
				return reflect.ValueOf(ts).Elem()
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			value := tt.setupValue()

			err := action.applyDefaultsRec(value)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if !tt.expectedError && tt.validateFunc != nil {
				tt.validateFunc(t, value)
			}
		})
	}
}

func TestIdsecServiceExecAction_resolveActionArgs(t *testing.T) {
	tests := []struct {
		name          string
		setupCmd      func() *cobra.Command
		schema        interface{}
		expectedError bool
		validateFunc  func(t *testing.T, result []reflect.Value)
	}{
		{
			name: "success_boolean_false_not_overridden_by_default_true",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().Bool("test-bool", false, "test flag")
				// User explicitly sets it to false
				_ = cmd.Flags().Set("test-bool", "false")
				return cmd
			},
			schema: &struct {
				TestBool bool `mapstructure:"test_bool" flag:"test-bool" default:"true"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, result []reflect.Value) {
				if len(result) != 1 {
					t.Fatalf("Expected 1 result value, got %d", len(result))
				}
				schema := result[0].Interface().(*struct {
					TestBool bool `mapstructure:"test_bool" flag:"test-bool" default:"true"`
				})
				if schema.TestBool != false {
					t.Errorf("User set test-bool=false, but got [%v] - overwrote the user's input", schema.TestBool)
				}
			},
		},
		{
			name: "success_boolean_true_not_overridden",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().Bool("test-bool", false, "test flag")
				_ = cmd.Flags().Set("test-bool", "true")
				return cmd
			},
			schema: &struct {
				TestBool bool `mapstructure:"test_bool" flag:"test-bool" default:"true"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, result []reflect.Value) {
				if len(result) != 1 {
					t.Fatalf("Expected 1 result value, got %d", len(result))
				}
				schema := result[0].Interface().(*struct {
					TestBool bool `mapstructure:"test_bool" flag:"test-bool" default:"true"`
				})
				if schema.TestBool != true {
					t.Errorf("Expected true, got %v", schema.TestBool)
				}
			},
		},
		{
			name: "success_int_zero_not_overridden_by_default_nonzero",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().Int("test-int", 0, "test flag")
				// User explicitly sets it to 0
				_ = cmd.Flags().Set("test-int", "0")
				return cmd
			},
			schema: &struct {
				TestInt int `mapstructure:"test_int" flag:"test-int" default:"1234"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, result []reflect.Value) {
				if len(result) != 1 {
					t.Fatalf("Expected 1 result value, got %d", len(result))
				}
				schema := result[0].Interface().(*struct {
					TestInt int `mapstructure:"test_int" flag:"test-int" default:"1234"`
				})
				if schema.TestInt != 0 {
					t.Errorf("User set test-int=0, but got [%v] - overwrote the user's input", schema.TestInt)
				}
			},
		},
		{
			name: "success_string_empty_not_overridden_by_default",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("test-str", "", "test flag")
				// User explicitly sets it to empty string
				_ = cmd.Flags().Set("test-str", "")
				return cmd
			},
			schema: &struct {
				TestStr string `mapstructure:"test_str" flag:"test-str" default:"default_value"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, result []reflect.Value) {
				if len(result) != 1 {
					t.Fatalf("Expected 1 result value, got %d", len(result))
				}
				schema := result[0].Interface().(*struct {
					TestStr string `mapstructure:"test_str" flag:"test-str" default:"default_value"`
				})
				if schema.TestStr != "" {
					t.Errorf("User set test-str='', but got [%v] - overwrote the user's input", schema.TestStr)
				}
			},
		},
		{
			name: "success_omitted_flag_gets_default",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().Bool("test-bool", false, "test-bool flag")
				cmd.Flags().String("name", "", "name flag")
				cmd.Flags().Int("count", 0, "count flag")
				// Don't set the flags - user omitted it
				return cmd
			},
			schema: &struct {
				TestBool bool   `mapstructure:"test_bool" flag:"test-bool" default:"true"`
				Name     string `mapstructure:"name" flag:"name" default:"default-name"`
				Count    int    `mapstructure:"count" flag:"count" default:"100"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, result []reflect.Value) {
				if len(result) != 1 {
					t.Fatalf("Expected 1 result value, got %d", len(result))
				}
				schema := result[0].Interface().(*struct {
					TestBool bool   `mapstructure:"test_bool" flag:"test-bool" default:"true"`
					Name     string `mapstructure:"name" flag:"name" default:"default-name"`
					Count    int    `mapstructure:"count" flag:"count" default:"100"`
				})
				if schema.TestBool != true || schema.Name != "default-name" || schema.Count != 100 {
					t.Errorf("Defaults not applied correctly: %+v", schema)
				}
			},
		},
		{
			name: "success_nonzero_values_not_overridden",
			setupCmd: func() *cobra.Command {
				cmd := &cobra.Command{}
				cmd.Flags().String("name", "", "name flag")
				cmd.Flags().Int("count", 0, "count flag")
				_ = cmd.Flags().Set("name", "my-database")
				_ = cmd.Flags().Set("count", "42")
				return cmd
			},
			schema: &struct {
				Name  string `mapstructure:"name" flag:"name" default:"default-name"`
				Count int    `mapstructure:"count" flag:"count" default:"100"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, result []reflect.Value) {
				if len(result) != 1 {
					t.Fatalf("Expected 1 result value, got %d", len(result))
				}
				schema := result[0].Interface().(*struct {
					Name  string `mapstructure:"name" flag:"name" default:"default-name"`
					Count int    `mapstructure:"count" flag:"count" default:"100"`
				})
				if schema.Name != "my-database" {
					t.Errorf("Expected 'my-database', got %v", schema.Name)
				}
				if schema.Count != 42 {
					t.Errorf("Expected 42, got %v", schema.Count)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			action := NewIdsecServiceExecAction(nil)
			cmd := tt.setupCmd()
			execCmd := &cobra.Command{}
			execCmd.PersistentFlags().String("request-file", "", "request file")

			result, err := action.resolveActionArgs(cmd, execCmd, tt.schema)

			if tt.expectedError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if !tt.expectedError && tt.validateFunc != nil {
				tt.validateFunc(t, result)
			}
		})
	}
}
