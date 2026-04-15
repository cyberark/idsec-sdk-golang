package services

import (
	"fmt"
	"slices"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
)

// releasedFeaturesOnly controls whether Enable attribute filtering is applied.
// Set via ldflags: -ldflags "-X github.com/cyberark/idsec-sdk-golang/pkg/services.releasedFeaturesOnly=true"
var releasedFeaturesOnly = "false"

// isEnableAttributeActive returns true if Enable attribute filtering is active.
func isEnableAttributeActive() bool {
	return releasedFeaturesOnly == "true"
}

// IdsecServiceConfig defines the configuration for an Idsec service.
type IdsecServiceConfig struct {
	ServiceName                string
	Enabled                    *bool
	RequiredAuthenticatorNames []string
	OptionalAuthenticatorNames []string
	ActionsConfigurations      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition
	ActionSchemas              map[string]interface{}
}

// IdsecService is an interface that defines the methods for an Idsec service.
// All services must implement this interface including telemetry support for tracking
// service usage and operations.
type IdsecService interface {
	ServiceConfig() IdsecServiceConfig

	// AddExtraContextField adds a custom context field to telemetry data.
	// This allows services to provide additional context for telemetry tracking.
	// Returns an error if the service client is not properly initialized.
	AddExtraContextField(name, shortName, value string) error

	// ClearExtraContext removes all extra context fields from telemetry data.
	// This should be called after operations complete to ensure clean telemetry state.
	// Returns an error if the service client is not properly initialized.
	ClearExtraContext() error
}

// IdsecBaseService is a struct that implements the IdsecService interface and provides base functionality for Idsec services.
type IdsecBaseService struct {
	Service        IdsecService
	Logger         *common.IdsecLogger
	authenticators []auth.IdsecAuth
}

// NewIdsecBaseService creates a new instance of IdsecBaseService with the provided service and authenticators.
func NewIdsecBaseService(service IdsecService, authenticators ...auth.IdsecAuth) (*IdsecBaseService, error) {
	baseService := &IdsecBaseService{
		Service:        service,
		Logger:         common.GetLogger("IdsecBaseService", common.Unknown),
		authenticators: make([]auth.IdsecAuth, 0),
	}

	if authenticators != nil {
		baseService.authenticators = append(baseService.authenticators, authenticators...)
	}
	var givenAuthNames []string
	for _, authenticator := range baseService.authenticators {
		givenAuthNames = append(givenAuthNames, authenticator.AuthenticatorName())
	}

	config := service.ServiceConfig()
	for _, requiredAuth := range config.RequiredAuthenticatorNames {
		if !slices.Contains(givenAuthNames, requiredAuth) {
			return nil, fmt.Errorf("%s missing required authenticators for service", config.ServiceName)
		}
	}

	return baseService, nil
}

// Authenticators returns the list of authenticators for the IdsecBaseService.
func (s *IdsecBaseService) Authenticators() []auth.IdsecAuth {
	return s.authenticators
}

// Authenticator returns the authenticator with the specified name from the IdsecBaseService.
func (s *IdsecBaseService) Authenticator(authName string) (auth.IdsecAuth, error) {
	for _, authenticator := range s.authenticators {
		if authenticator.AuthenticatorName() == authName {
			return authenticator, nil
		}
	}
	return nil, fmt.Errorf("%s Failed to find authenticator %s", s.Service.ServiceConfig().ServiceName, authName)
}

// HasAuthenticator checks if the IdsecBaseService has an authenticator with the specified name.
func (s *IdsecBaseService) HasAuthenticator(authName string) bool {
	for _, authenticator := range s.authenticators {
		if authenticator.AuthenticatorName() == authName {
			return true
		}
	}
	return false
}

var (
	serviceRegistry  = make(map[string]IdsecServiceConfig)
	topLevelServices []string
)

// filterEnabledActions removes disabled actions from the configuration.
// Only filters top-level actions - subactions are not individually filtered.
func filterEnabledActions(config IdsecServiceConfig) IdsecServiceConfig {
	filtered := IdsecServiceConfig{
		ServiceName:                config.ServiceName,
		Enabled:                    config.Enabled,
		RequiredAuthenticatorNames: config.RequiredAuthenticatorNames,
		OptionalAuthenticatorNames: config.OptionalAuthenticatorNames,
		ActionsConfigurations:      make(map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition),
	}

	for actionType, actionDefs := range config.ActionsConfigurations {
		enabledActions := make([]actions.IdsecServiceActionDefinition, 0)
		for _, actionDef := range actionDefs {
			if actionDef.IsEnabled() {
				enabledActions = append(enabledActions, actionDef)
			}
		}
		if len(enabledActions) > 0 {
			filtered.ActionsConfigurations[actionType] = enabledActions
		}
	}

	return filtered
}

// Register registers a new Idsec service configuration.
// If Enable attribute filtering is active and the service is disabled (Enabled = false),
// it is silently skipped. Disabled actions within the service are filtered out before registration.
func Register(serviceConfig IdsecServiceConfig, topLevel bool) error {
	// Skip disabled services silently (only when filtering is active)
	if isEnableAttributeActive() && serviceConfig.Enabled != nil && !*serviceConfig.Enabled {
		return nil
	}

	if _, exists := serviceRegistry[serviceConfig.ServiceName]; exists {
		return fmt.Errorf("service %s already registered", serviceConfig.ServiceName)
	}

	// Filter disabled top-level actions (only when filtering is active)
	configToRegister := serviceConfig
	if isEnableAttributeActive() {
		configToRegister = filterEnabledActions(serviceConfig)
	}

	serviceRegistry[configToRegister.ServiceName] = configToRegister
	if topLevel {
		topLevelServices = append(topLevelServices, configToRegister.ServiceName)
	}
	return nil
}

// GetServiceConfig retrieves the Idsec service configuration by service name.
func GetServiceConfig(serviceName string) (IdsecServiceConfig, error) {
	if config, exists := serviceRegistry[serviceName]; exists {
		return config, nil
	}
	return IdsecServiceConfig{}, fmt.Errorf("service %s not registered", serviceName)
}

// AllServiceConfigs returns a slice of all registered Idsec service configurations.
func AllServiceConfigs() []IdsecServiceConfig {
	configs := make([]IdsecServiceConfig, 0, len(serviceRegistry))
	for _, config := range serviceRegistry {
		configs = append(configs, config)
	}
	return configs
}

// TopLevelServiceConfigs returns a slice of all registered top-level Idsec service configurations.
func TopLevelServiceConfigs() []IdsecServiceConfig {
	configs := make([]IdsecServiceConfig, 0, len(topLevelServices))
	for _, serviceName := range topLevelServices {
		if config, exists := serviceRegistry[serviceName]; exists {
			configs = append(configs, config)
		}
	}
	return configs
}
