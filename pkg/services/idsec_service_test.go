package services

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
)

// Helper function to create a bool pointer
func boolPtr(b bool) *bool {
	return &b
}

// mockActionDefinition is a test implementation of IdsecServiceActionDefinition
type mockActionDefinition struct {
	name    string
	enabled *bool
}

func (m *mockActionDefinition) ActionType() actions.IdsecServiceActionType {
	return actions.IdsecServiceActionTypeCLI
}

func (m *mockActionDefinition) ActionDefinitionName() string {
	return m.name
}

func (m *mockActionDefinition) IsEnabled() bool {
	return m.enabled == nil || *m.enabled
}

// resetRegistry clears the service registry for test isolation
func resetRegistry() {
	serviceRegistry = make(map[string]IdsecServiceConfig)
	topLevelServices = []string{}
}

// setEnableAttributeActive sets the flag for testing and returns a cleanup function
func setEnableAttributeActive(active bool) func() {
	original := releasedFeaturesOnly
	if active {
		releasedFeaturesOnly = "true"
	} else {
		releasedFeaturesOnly = "false"
	}
	return func() {
		releasedFeaturesOnly = original
	}
}

func TestRegister_DisabledService_NotRegistered_WhenFlagOn(t *testing.T) {
	resetRegistry()
	cleanup := setEnableAttributeActive(true)
	defer cleanup()

	config := IdsecServiceConfig{
		ServiceName: "disabled-service",
		Enabled:     boolPtr(false),
	}

	err := Register(config, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify service was not registered
	_, err = GetServiceConfig("disabled-service")
	if err == nil {
		t.Error("expected error for disabled service, got nil")
	}

	// Verify not in top level services
	configs := TopLevelServiceConfigs()
	for _, c := range configs {
		if c.ServiceName == "disabled-service" {
			t.Error("disabled service should not be in top level services")
		}
	}
}

func TestRegister_DisabledService_Registered_WhenFlagOff(t *testing.T) {
	resetRegistry()
	cleanup := setEnableAttributeActive(false)
	defer cleanup()

	config := IdsecServiceConfig{
		ServiceName: "disabled-service-flag-off",
		Enabled:     boolPtr(false),
	}

	err := Register(config, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify service WAS registered (flag is off, so filtering is skipped)
	_, err = GetServiceConfig("disabled-service-flag-off")
	if err != nil {
		t.Errorf("expected service to be registered when flag is off, got error: %v", err)
	}
}

func TestRegister_NilEnabled_Registered(t *testing.T) {
	resetRegistry()

	config := IdsecServiceConfig{
		ServiceName: "nil-enabled-service",
		Enabled:     nil, // nil means enabled (backwards compatible)
	}

	err := Register(config, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify service was registered
	_, err = GetServiceConfig("nil-enabled-service")
	if err != nil {
		t.Errorf("expected service to be registered, got error: %v", err)
	}
}

func TestRegister_ExplicitlyEnabled_Registered(t *testing.T) {
	resetRegistry()

	config := IdsecServiceConfig{
		ServiceName: "explicitly-enabled-service",
		Enabled:     boolPtr(true),
	}

	err := Register(config, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify service was registered
	_, err = GetServiceConfig("explicitly-enabled-service")
	if err != nil {
		t.Errorf("expected service to be registered, got error: %v", err)
	}
}

func TestRegister_DisabledAction_Filtered_WhenFlagOn(t *testing.T) {
	resetRegistry()
	cleanup := setEnableAttributeActive(true)
	defer cleanup()

	enabledAction := &mockActionDefinition{name: "enabled-action", enabled: nil}
	disabledAction := &mockActionDefinition{name: "disabled-action", enabled: boolPtr(false)}

	config := IdsecServiceConfig{
		ServiceName: "service-with-actions",
		Enabled:     nil,
		ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
			actions.IdsecServiceActionTypeCLI: {enabledAction, disabledAction},
		},
	}

	err := Register(config, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify service was registered with only enabled action
	registeredConfig, err := GetServiceConfig("service-with-actions")
	if err != nil {
		t.Fatalf("expected service to be registered, got error: %v", err)
	}

	cliActions := registeredConfig.ActionsConfigurations[actions.IdsecServiceActionTypeCLI]
	if len(cliActions) != 1 {
		t.Errorf("expected 1 enabled action, got %d", len(cliActions))
	}

	if cliActions[0].ActionDefinitionName() != "enabled-action" {
		t.Errorf("expected enabled-action, got %s", cliActions[0].ActionDefinitionName())
	}
}

func TestRegister_DisabledAction_NotFiltered_WhenFlagOff(t *testing.T) {
	resetRegistry()
	cleanup := setEnableAttributeActive(false)
	defer cleanup()

	enabledAction := &mockActionDefinition{name: "enabled-action", enabled: nil}
	disabledAction := &mockActionDefinition{name: "disabled-action", enabled: boolPtr(false)}

	config := IdsecServiceConfig{
		ServiceName: "service-with-actions-flag-off",
		Enabled:     nil,
		ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
			actions.IdsecServiceActionTypeCLI: {enabledAction, disabledAction},
		},
	}

	err := Register(config, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify service was registered with ALL actions (flag is off)
	registeredConfig, err := GetServiceConfig("service-with-actions-flag-off")
	if err != nil {
		t.Fatalf("expected service to be registered, got error: %v", err)
	}

	cliActions := registeredConfig.ActionsConfigurations[actions.IdsecServiceActionTypeCLI]
	if len(cliActions) != 2 {
		t.Errorf("expected 2 actions when flag is off, got %d", len(cliActions))
	}
}

func TestRegister_AllActionsDisabled_EmptyConfig_WhenFlagOn(t *testing.T) {
	resetRegistry()
	cleanup := setEnableAttributeActive(true)
	defer cleanup()

	disabledAction1 := &mockActionDefinition{name: "disabled-action-1", enabled: boolPtr(false)}
	disabledAction2 := &mockActionDefinition{name: "disabled-action-2", enabled: boolPtr(false)}

	config := IdsecServiceConfig{
		ServiceName: "service-all-disabled",
		Enabled:     nil,
		ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
			actions.IdsecServiceActionTypeCLI: {disabledAction1, disabledAction2},
		},
	}

	err := Register(config, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify service was registered with empty actions
	registeredConfig, err := GetServiceConfig("service-all-disabled")
	if err != nil {
		t.Fatalf("expected service to be registered, got error: %v", err)
	}

	cliActions := registeredConfig.ActionsConfigurations[actions.IdsecServiceActionTypeCLI]
	if len(cliActions) != 0 {
		t.Errorf("expected 0 actions (all disabled), got %d", len(cliActions))
	}
}

func TestIsEnabled_NilReturnsTrue(t *testing.T) {
	action := &actions.IdsecServiceBaseActionDefinition{
		ActionName: "test-action",
		Enabled:    nil,
	}

	if !action.IsEnabled() {
		t.Error("expected IsEnabled() to return true for nil Enabled")
	}
}

func TestIsEnabled_TrueReturnsTrue(t *testing.T) {
	action := &actions.IdsecServiceBaseActionDefinition{
		ActionName: "test-action",
		Enabled:    boolPtr(true),
	}

	if !action.IsEnabled() {
		t.Error("expected IsEnabled() to return true for Enabled=true")
	}
}

func TestIsEnabled_FalseReturnsFalse(t *testing.T) {
	action := &actions.IdsecServiceBaseActionDefinition{
		ActionName: "test-action",
		Enabled:    boolPtr(false),
	}

	if action.IsEnabled() {
		t.Error("expected IsEnabled() to return false for Enabled=false")
	}
}

func TestFilterEnabledActions_PreservesOtherFields(t *testing.T) {
	enabledAction := &mockActionDefinition{name: "enabled-action", enabled: nil}

	config := IdsecServiceConfig{
		ServiceName:                "test-service",
		Enabled:                    boolPtr(true),
		RequiredAuthenticatorNames: []string{"auth1", "auth2"},
		OptionalAuthenticatorNames: []string{"opt1"},
		ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
			actions.IdsecServiceActionTypeCLI: {enabledAction},
		},
	}

	filtered := filterEnabledActions(config)

	if filtered.ServiceName != config.ServiceName {
		t.Errorf("ServiceName mismatch: expected %s, got %s", config.ServiceName, filtered.ServiceName)
	}

	if len(filtered.RequiredAuthenticatorNames) != len(config.RequiredAuthenticatorNames) {
		t.Errorf("RequiredAuthenticatorNames length mismatch: expected %d, got %d",
			len(config.RequiredAuthenticatorNames), len(filtered.RequiredAuthenticatorNames))
	}

	if len(filtered.OptionalAuthenticatorNames) != len(config.OptionalAuthenticatorNames) {
		t.Errorf("OptionalAuthenticatorNames length mismatch: expected %d, got %d",
			len(config.OptionalAuthenticatorNames), len(filtered.OptionalAuthenticatorNames))
	}
}

func TestRegister_MultipleActionTypes_FilteredIndependently_WhenFlagOn(t *testing.T) {
	resetRegistry()
	cleanup := setEnableAttributeActive(true)
	defer cleanup()

	enabledCLI := &mockActionDefinition{name: "enabled-cli", enabled: nil}
	disabledCLI := &mockActionDefinition{name: "disabled-cli", enabled: boolPtr(false)}

	enabledOther := &mockActionDefinition{name: "enabled-other", enabled: nil}

	config := IdsecServiceConfig{
		ServiceName: "multi-type-service",
		Enabled:     nil,
		ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
			actions.IdsecServiceActionTypeCLI:            {enabledCLI, disabledCLI},
			actions.IdsecServiceActionType("other-type"): {enabledOther},
		},
	}

	err := Register(config, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	registeredConfig, err := GetServiceConfig("multi-type-service")
	if err != nil {
		t.Fatalf("expected service to be registered, got error: %v", err)
	}

	// Verify CLI actions filtered
	cliActions := registeredConfig.ActionsConfigurations[actions.IdsecServiceActionTypeCLI]
	if len(cliActions) != 1 {
		t.Errorf("expected 1 CLI action, got %d", len(cliActions))
	}

	// Verify other action type preserved
	otherActions := registeredConfig.ActionsConfigurations[actions.IdsecServiceActionType("other-type")]
	if len(otherActions) != 1 {
		t.Errorf("expected 1 other action, got %d", len(otherActions))
	}
}

func TestIsEnableAttributeActive_DefaultFalse(t *testing.T) {
	// Reset to default
	releasedFeaturesOnly = "false"

	if isEnableAttributeActive() {
		t.Error("expected isEnableAttributeActive() to return false by default")
	}
}

func TestIsEnableAttributeActive_TrueWhenSet(t *testing.T) {
	cleanup := setEnableAttributeActive(true)
	defer cleanup()

	if !isEnableAttributeActive() {
		t.Error("expected isEnableAttributeActive() to return true when set")
	}
}
