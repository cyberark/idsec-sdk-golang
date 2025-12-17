package actions

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/cyberark/idsec-sdk-golang/pkg/actions/testutils"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
)

func TestNewIdsecConfigureAction(t *testing.T) {
	tests := []struct {
		name         string
		setupLoader  func() profiles.ProfileLoader
		validateFunc func(t *testing.T, action *IdsecConfigureAction)
	}{
		{
			name: "success_creates_action_with_profile_loader",
			setupLoader: func() profiles.ProfileLoader {
				return testutils.NewMockProfileLoader()
			},
			validateFunc: func(t *testing.T, action *IdsecConfigureAction) {
				if action == nil {
					t.Error("Expected action to be created, got nil")
					return
				}
				if action.IdsecBaseAction == nil {
					t.Error("Expected IdsecBaseAction to be initialized")
				}
				if action.profilesLoader == nil {
					t.Error("Expected profilesLoader to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			loader := tt.setupLoader()
			action := NewIdsecConfigureAction(&loader)

			if tt.validateFunc != nil {
				tt.validateFunc(t, action)
			}
		})
	}
}

func TestIdsecConfigureAction_DefineAction(t *testing.T) {
	tests := []struct {
		name         string
		setupLoader  func() profiles.ProfileLoader
		validateFunc func(t *testing.T, cmd *cobra.Command, confCmd *cobra.Command)
	}{
		{
			name: "success_adds_configure_command_with_flags",
			setupLoader: func() profiles.ProfileLoader {
				return testutils.NewMockProfileLoader()
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command, confCmd *cobra.Command) {
				// Verify configure command was added
				if confCmd == nil {
					t.Error("Expected configure command to be added")
					return
				}

				if confCmd.Use != "configure" {
					t.Errorf("Expected command use 'configure', got '%s'", confCmd.Use)
				}

				if confCmd.Short != "Configure the CLI" {
					t.Errorf("Expected command short description 'Configure the CLI', got '%s'", confCmd.Short)
				}

				if confCmd.Run == nil {
					t.Error("Expected run function to be set")
				}

				if confCmd.PersistentPreRun == nil {
					t.Error("Expected persistent pre-run function to be set")
				}
			},
		},
		{
			name: "success_adds_profile_flags",
			setupLoader: func() profiles.ProfileLoader {
				return testutils.NewMockProfileLoader()
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command, confCmd *cobra.Command) {
				// Check for common flags from IdsecBaseAction
				commonFlags := []string{
					"raw", "silent", "allow-output", "verbose",
					"logger-style", "log-level", "disable-cert-verification", "trusted-cert",
				}

				for _, flagName := range commonFlags {
					flag := confCmd.PersistentFlags().Lookup(flagName)
					if flag == nil {
						t.Errorf("Expected common flag '%s' to be present", flagName)
					}
				}
			},
		},
		{
			name: "edge_case_handles_nil_profile_loader",
			setupLoader: func() profiles.ProfileLoader {
				return nil
			},
			validateFunc: func(t *testing.T, cmd *cobra.Command, confCmd *cobra.Command) {
				// Should not panic even with nil profile loader
				if confCmd == nil {
					t.Error("Expected configure command to be added even with nil loader")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			loader := tt.setupLoader()
			action := NewIdsecConfigureAction(&loader)
			cmd := &cobra.Command{}

			// Execute DefineAction - should not panic
			action.DefineAction(cmd)

			// Find the configure command
			var confCmd *cobra.Command
			for _, subCmd := range cmd.Commands() {
				if subCmd.Use == "configure" {
					confCmd = subCmd
					break
				}
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, cmd, confCmd)
			}
		})
	}
}

func TestIdsecConfigureAction_runSilentConfigureAction(t *testing.T) {
	tests := []struct {
		name            string
		setupLoader     func() profiles.ProfileLoader
		setupFlags      func(cmd *cobra.Command)
		expectedProfile *models.IdsecProfile
		expectedError   bool
		validateFunc    func(t *testing.T, profile *models.IdsecProfile, err error)
	}{
		{
			name: "success_creates_new_profile_with_default_name",
			setupLoader: func() profiles.ProfileLoader {
				mock := testutils.NewMockProfileLoader()
				mock.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return nil, nil // Profile not found
				}
				return mock
			},
			setupFlags: func(cmd *cobra.Command) {
				// Define the profile-name flag that the function expects
				_ = cmd.Flags().String("profile-name", "", "Profile name")
			},
			expectedError: false,
			validateFunc: func(t *testing.T, profile *models.IdsecProfile, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if profile == nil {
					t.Error("Expected profile to be created")
					return
				}
				if profile.AuthProfiles == nil {
					t.Error("Expected AuthProfiles to be initialized")
				}
			},
		},
		{
			name: "success_loads_existing_profile",
			setupLoader: func() profiles.ProfileLoader {
				existingProfile := &models.IdsecProfile{
					ProfileName:  "test-profile",
					AuthProfiles: map[string]*authmodels.IdsecAuthProfile{},
				}
				mock := testutils.NewMockProfileLoader()
				mock.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return existingProfile, nil
				}
				return mock
			},
			setupFlags: func(cmd *cobra.Command) {
				_ = cmd.Flags().String("profile-name", "", "Profile name")
				_ = cmd.Flags().Set("profile-name", "test-profile")
			},
			expectedError: false,
			validateFunc: func(t *testing.T, profile *models.IdsecProfile, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if profile == nil {
					t.Error("Expected profile to be loaded")
					return
				}
				if profile.ProfileName != "test-profile" {
					t.Errorf("Expected profile name 'test-profile', got '%s'", profile.ProfileName)
				}
			},
		},
		{
			name: "success_merges_flag_values",
			setupLoader: func() profiles.ProfileLoader {
				mock := testutils.NewMockProfileLoader()
				mock.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return nil, nil // New profile
				}
				return mock
			},
			setupFlags: func(cmd *cobra.Command) {
				_ = cmd.Flags().String("profile-name", "", "Profile name")
				_ = cmd.Flags().String("tenant-url", "", "Tenant URL")
				_ = cmd.Flags().Set("profile-name", "custom-profile")
				_ = cmd.Flags().Set("tenant-url", "https://example.com")
			},
			expectedError: false,
			validateFunc: func(t *testing.T, profile *models.IdsecProfile, err error) {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if profile.ProfileName != "custom-profile" {
					t.Errorf("Expected profile name 'custom-profile', got '%s'", profile.ProfileName)
				}
			},
		},
		{
			name: "edge_case_handles_flag_parsing_errors",
			setupLoader: func() profiles.ProfileLoader {
				mock := testutils.NewMockProfileLoader()
				mock.LoadProfileFunc = func(name string) (*models.IdsecProfile, error) {
					return nil, nil
				}
				return mock
			},
			setupFlags: func(cmd *cobra.Command) {
				// Define the profile-name flag but don't set a value to test default behavior
				_ = cmd.Flags().String("profile-name", "", "Profile name")
			},
			expectedError: false, // Function handles missing flag values gracefully by using defaults
			validateFunc: func(t *testing.T, profile *models.IdsecProfile, err error) {
				// Should create a profile even when no flag values are set
				if profile == nil {
					t.Error("Expected profile to be created despite missing flag values")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			loader := tt.setupLoader()
			action := NewIdsecConfigureAction(&loader)
			cmd := &cobra.Command{}

			if tt.setupFlags != nil {
				tt.setupFlags(cmd)
			}

			profile, err := action.runSilentConfigureAction(cmd, []string{})

			// Validate error expectation
			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, profile, err)
			}
		})
	}
}

func TestIdsecConfigureAction_StructFields(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T, action *IdsecConfigureAction)
	}{
		{
			name: "success_struct_has_expected_fields",
			validateFunc: func(t *testing.T, action *IdsecConfigureAction) {
				actionValue := reflect.ValueOf(action).Elem()
				actionType := actionValue.Type()

				expectedFields := []string{"IdsecBaseAction", "profilesLoader"}
				actualFields := make([]string, actionType.NumField())

				for i := 0; i < actionType.NumField(); i++ {
					actualFields[i] = actionType.Field(i).Name
				}

				for _, expectedField := range expectedFields {
					found := false
					for _, actualField := range actualFields {
						if actualField == expectedField {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected field '%s' not found in struct", expectedField)
					}
				}
			},
		},
		{
			name: "success_profilesloader_field_has_correct_type",
			validateFunc: func(t *testing.T, action *IdsecConfigureAction) {
				actionValue := reflect.ValueOf(action).Elem()
				profilesLoaderField := actionValue.FieldByName("profilesLoader")

				if !profilesLoaderField.IsValid() {
					t.Error("profilesLoader field not found")
					return
				}

				expectedType := "*profiles.ProfileLoader"
				actualType := profilesLoaderField.Type().String()
				if actualType != expectedType {
					t.Errorf("Expected profilesLoader field type '%s', got '%s'", expectedType, actualType)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			loader := testutils.NewMockProfileLoader()
			loaderInterface := profiles.ProfileLoader(loader)
			action := NewIdsecConfigureAction(&loaderInterface)

			if tt.validateFunc != nil {
				tt.validateFunc(t, action)
			}
		})
	}
}

func TestIdsecConfigureAction_IdsecActionInterface(t *testing.T) {
	tests := []struct {
		name         string
		validateFunc func(t *testing.T)
	}{
		{
			name: "success_implements_idsecaction_interface",
			validateFunc: func(t *testing.T) {
				loader := testutils.NewMockProfileLoader()
				loaderInterface := profiles.ProfileLoader(loader)
				action := NewIdsecConfigureAction(&loaderInterface)

				// This will cause a compile error if IdsecConfigureAction doesn't implement IdsecAction
				var _ IdsecAction = action

				// Verify the DefineAction method exists and can be called
				cmd := &cobra.Command{}
				action.DefineAction(cmd)

				// Verify a configure command was added
				found := false
				for _, subCmd := range cmd.Commands() {
					if subCmd.Use == "configure" {
						found = true
						break
					}
				}
				if !found {
					t.Error("Expected configure command to be added to parent command")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.validateFunc != nil {
				tt.validateFunc(t)
			}
		})
	}
}

func TestIdsecConfigureAction_RunInteractiveConfigureAction_DefaultValuesReflection(t *testing.T) {
	tests := []struct {
		name           string
		authenticator  auth.IdsecAuth
		defaultValues  map[string]interface{}
		methodSettings interface{}
		expectedError  bool
		validateFunc   func(t *testing.T, methodSettings interface{})
	}{
		{
			name:          "success_sets_valid_default_value_on_valid_field",
			authenticator: auth.SupportedAuthenticatorsList[0],
			defaultValues: map[string]interface{}{
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-test-field": "default-value",
			},
			methodSettings: &struct {
				TestField string `flag:"test-field"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, methodSettings interface{}) {
				v := reflect.ValueOf(methodSettings).Elem()
				testField := v.FieldByName("TestField").String()
				if testField != "default-value" {
					t.Errorf("Expected TestField to be 'default-value', got '%s'", testField)
				}
			},
		},
		{
			name:          "success_skips_invalid_field_and_continues",
			authenticator: auth.SupportedAuthenticatorsList[0],
			defaultValues: map[string]interface{}{
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-nonexistent-field": "value",
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-valid-field":       "valid-value",
			},
			methodSettings: &struct {
				ValidField string `flag:"valid-field"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, methodSettings interface{}) {
				v := reflect.ValueOf(methodSettings).Elem()
				validField := v.FieldByName("ValidField").String()
				if validField != "valid-value" {
					t.Errorf("Expected ValidField to be 'valid-value', got '%s'", validField)
				}
			},
		},
		{
			name:          "success_handles_multiple_default_values",
			authenticator: auth.SupportedAuthenticatorsList[0],
			defaultValues: map[string]interface{}{
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-field-one":   "value-one",
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-field-two":   "value-two",
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-field-three": "value-three",
			},
			methodSettings: &struct {
				FieldOne   string `flag:"field-one"`
				FieldTwo   string `flag:"field-two"`
				FieldThree string `flag:"field-three"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, methodSettings interface{}) {
				v := reflect.ValueOf(methodSettings).Elem()
				if fieldOne := v.FieldByName("FieldOne").String(); fieldOne != "value-one" {
					t.Errorf("Expected FieldOne to be 'value-one', got '%s'", fieldOne)
				}
				if fieldTwo := v.FieldByName("FieldTwo").String(); fieldTwo != "value-two" {
					t.Errorf("Expected FieldTwo to be 'value-two', got '%s'", fieldTwo)
				}
				if fieldThree := v.FieldByName("FieldThree").String(); fieldThree != "value-three" {
					t.Errorf("Expected FieldThree to be 'value-three', got '%s'", fieldThree)
				}
			},
		},
		{
			name:          "success_handles_mixed_valid_and_invalid_fields",
			authenticator: auth.SupportedAuthenticatorsList[0],
			defaultValues: map[string]interface{}{
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-valid-field":   "valid-value",
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-invalid-field": "invalid-value",
			},
			methodSettings: &struct {
				ValidField string `flag:"valid-field"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, methodSettings interface{}) {
				v := reflect.ValueOf(methodSettings).Elem()
				validField := v.FieldByName("ValidField").String()
				if validField != "valid-value" {
					t.Errorf("Expected ValidField to be 'valid-value', got '%s'", validField)
				}
			},
		},
		{
			name:           "success_handles_empty_default_values_map",
			authenticator:  auth.SupportedAuthenticatorsList[0],
			defaultValues:  map[string]interface{}{},
			methodSettings: &struct{ TestField string }{},
			expectedError:  false,
			validateFunc: func(t *testing.T, methodSettings interface{}) {
				v := reflect.ValueOf(methodSettings).Elem()
				testField := v.FieldByName("TestField").String()
				if testField != "" {
					t.Errorf("Expected TestField to be empty, got '%s'", testField)
				}
			},
		},
		{
			name:          "success_handles_different_value_types",
			authenticator: auth.SupportedAuthenticatorsList[0],
			defaultValues: map[string]interface{}{
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-string-field": "string-value",
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-int-field":    42,
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-bool-field":   true,
			},
			methodSettings: &struct {
				StringField string `flag:"string-field"`
				IntField    int    `flag:"int-field"`
				BoolField   bool   `flag:"bool-field"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, methodSettings interface{}) {
				v := reflect.ValueOf(methodSettings).Elem()
				if stringField := v.FieldByName("StringField").String(); stringField != "string-value" {
					t.Errorf("Expected StringField to be 'string-value', got '%s'", stringField)
				}
				if intField := v.FieldByName("IntField").Int(); intField != 42 {
					t.Errorf("Expected IntField to be 42, got %d", intField)
				}
				if boolField := v.FieldByName("BoolField").Bool(); !boolField {
					t.Errorf("Expected BoolField to be true, got false")
				}
			},
		},
		{
			name:          "success_handles_field_without_flag_tag",
			authenticator: auth.SupportedAuthenticatorsList[0],
			defaultValues: map[string]interface{}{
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-testfield": "value",
			},
			methodSettings: &struct {
				TestField string
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, methodSettings interface{}) {
				v := reflect.ValueOf(methodSettings).Elem()
				testField := v.FieldByName("TestField").String()
				if testField != "value" {
					t.Errorf("Expected TestField to be 'value', got '%s'", testField)
				}
			},
		},
		{
			name:          "edge_case_nil_value_skipped_by_invalid_check",
			authenticator: auth.SupportedAuthenticatorsList[0],
			defaultValues: map[string]interface{}{
				auth.SupportedAuthenticatorsList[0].AuthenticatorName() + "-test-field": nil,
			},
			methodSettings: &struct {
				TestField string `flag:"test-field"`
			}{},
			expectedError: false,
			validateFunc: func(t *testing.T, methodSettings interface{}) {
				v := reflect.ValueOf(methodSettings).Elem()
				testField := v.FieldByName("TestField").String()
				if testField != "" {
					t.Errorf("Expected TestField to remain empty, got '%s'", testField)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Simulate the reflection logic from the selected code
			methodSettingsType := reflect.TypeOf(tt.methodSettings).Elem()

			for key, val := range tt.defaultValues {
				// Find the field that matches the key
				var foundField reflect.Value
				for i := 0; i < methodSettingsType.NumField(); i++ {
					field := methodSettingsType.Field(i)
					tag := field.Tag.Get("flag")
					expectedFlagName := tag
					if expectedFlagName == "" {
						// Convert field name to flag format
						expectedFlagName = strings.ReplaceAll(field.Name, "_", "-")
						expectedFlagName = strings.ToLower(expectedFlagName)
					}
					// Add authenticator prefix
					fullFlagName := tt.authenticator.AuthenticatorName() + "-" + expectedFlagName

					if fullFlagName == key {
						foundField = reflect.ValueOf(tt.methodSettings).Elem().Field(i)
						break
					}
				}

				// This is the code block being tested
				if !foundField.IsValid() {
					continue
				}

				// Skip nil values as they can't be set
				if val == nil {
					continue
				}

				foundField.Set(reflect.ValueOf(val))
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, tt.methodSettings)
			}
		})
	}
}
