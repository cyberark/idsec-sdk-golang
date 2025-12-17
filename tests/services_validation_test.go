package tests

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"

	// Import all service packages via the official auto-generated registry (idsec_api_services.go)
	// This automatically imports ALL SDK services maintained by the genservices tool
	_ "github.com/cyberark/idsec-sdk-golang/pkg"
)

// TestAllServiceActionMappingsHaveSchemas validates that all ActionsMappings across all services
// have corresponding schema implementations.
//
// This test dynamically validates that every action string referenced in ActionsMappings and
// DataSourceAction for all registered services has a corresponding entry in their respective
// ActionToSchemaMap. This prevents runtime failures due to missing schema implementations
// without hardcoding expected values for any specific service.
//
// The test validates all Terraform resource and data source definitions across all services by:
//  1. Iterating through all registered service configurations
//  2. Extracting Terraform action definitions from each service
//  3. Validating ActionsMappings for each resource definition
//  4. Validating DataSourceAction for each data source definition
//  5. Ensuring each action string exists in the service's ActionToSchemaMap
//
// If any mapping is missing from a service's ActionToSchemaMap, the test will fail with a
// descriptive error indicating which action, service, and resource type is missing the schema
// implementation.
func TestAllServiceActionMappingsHaveSchemas(t *testing.T) {
	// Get all registered service configurations
	allConfigs := services.AllServiceConfigs()

	if len(allConfigs) == 0 {
		t.Skip("No service configurations registered")
	}

	for _, config := range allConfigs {
		t.Run(config.ServiceName, func(t *testing.T) {
			validateServiceActionMappings(t, config)
		})
	}
}

// validateServiceActionMappings validates action mappings for a specific service
func validateServiceActionMappings(t *testing.T, config services.IdsecServiceConfig) {
	// Extract Terraform resource definitions
	if resourceDefinitions, exists := config.ActionsConfigurations[actions.IdsecServiceActionTypeTerraformResource]; exists {
		for _, actionDef := range resourceDefinitions {
			if resourceDef, ok := actionDef.(*actions.IdsecServiceTerraformResourceActionDefinition); ok {
				validateTerraformResourceActions(t, config.ServiceName, resourceDef)
			}
		}
	}

	// Extract Terraform data source definitions
	if dataSourceDefinitions, exists := config.ActionsConfigurations[actions.IdsecServiceActionTypeTerraformDataSource]; exists {
		for _, actionDef := range dataSourceDefinitions {
			if dataSourceDef, ok := actionDef.(*actions.IdsecServiceTerraformDataSourceActionDefinition); ok {
				validateTerraformDataSourceActions(t, config.ServiceName, dataSourceDef)
			}
		}
	}
}

// validateTerraformResourceActions validates that all ActionsMappings have corresponding schemas
func validateTerraformResourceActions(t *testing.T, serviceName string, def *actions.IdsecServiceTerraformResourceActionDefinition) {
	t.Run(def.ActionName, func(t *testing.T) {
		for operation, actionString := range def.ActionsMappings {
			if _, exists := def.Schemas[actionString]; !exists {
				t.Errorf("Service '%s': Action '%s' (operation: %v) in resource '%s' is missing from ActionToSchemaMap",
					serviceName, actionString, operation, def.ActionName)
			}
		}
	})
}

// validateTerraformDataSourceActions validates that DataSourceAction has corresponding schema
func validateTerraformDataSourceActions(t *testing.T, serviceName string, def *actions.IdsecServiceTerraformDataSourceActionDefinition) {
	t.Run(def.ActionName+"_datasource", func(t *testing.T) {
		if def.DataSourceAction != "" {
			if _, exists := def.Schemas[def.DataSourceAction]; !exists {
				t.Errorf("Service '%s': DataSourceAction '%s' in data source '%s' is missing from ActionToSchemaMap",
					serviceName, def.DataSourceAction, def.ActionName)
			}
		}
	})
}
