package tests

import (
	"reflect"
	"strings"
	"testing"

	api "github.com/cyberark/idsec-sdk-golang/pkg"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"

	// Import all service packages via the official auto-generated registry (idsec_api_services.go)
	// This automatically imports ALL SDK services maintained by the genservices tool
	_ "github.com/cyberark/idsec-sdk-golang/pkg"
)

// TestAllCLIActionMethodsExist validates that all CLI actions have corresponding methods
// on their respective services.
//
// This test dynamically discovers all registered services and validates that every action
// defined in their CLI ActionToSchemaMap can be invoked via reflection. It ensures that:
//  1. Each action name can be transformed to a valid method name (e.g., "add-policy" -> "AddPolicy")
//  2. The corresponding method exists on the service interface
//  3. All actions have executable implementations
//
// This prevents runtime failures due to missing or misnamed methods without requiring
// manual test case registration for each service.
func TestAllCLIActionMethodsExist(t *testing.T) {
	// Get all registered service configurations
	allConfigs := services.AllServiceConfigs()

	if len(allConfigs) == 0 {
		t.Skip("No service configurations registered")
	}

	for _, config := range allConfigs {
		t.Run(config.ServiceName, func(t *testing.T) {
			validateCLIActionMethods(t, config)
		})
	}
}

// validateCLIActionMethods validates that all CLI actions have corresponding methods
func validateCLIActionMethods(t *testing.T, config services.IdsecServiceConfig) {
	// Extract action schemas from the service config
	if len(config.ActionSchemas) == 0 {
		t.Skip("No action schemas defined for this service")
		return
	}

	// Get the service type using IdsecAPI reflection
	serviceType := getServiceTypeFromAPI(config.ServiceName)
	if serviceType == nil {
		t.Skipf("Could not determine service type for %s", config.ServiceName)
		return
	}

	validateCLIActionDefinition(t, serviceType, config.ActionSchemas)
}

// serviceTypeMap is built once by scanning all IdsecAPI methods and mapping
// normalized (lowercase, no hyphens) names to their return types.
// This handles cases where the API method name doesn't match a naive PascalCase
// conversion of the service name (e.g., "sia-workspaces-target-sets" needs to
// match "SiaWorkspacestargetsets", not "SiaWorkspacesTargetSets").
var serviceTypeMap = buildServiceTypeMap()

func buildServiceTypeMap() map[string]reflect.Type {
	apiType := reflect.TypeOf(&api.IdsecAPI{})
	result := make(map[string]reflect.Type)

	for i := 0; i < apiType.NumMethod(); i++ {
		method := apiType.Method(i)
		if method.Type.NumOut() >= 1 {
			returnType := method.Type.Out(0)
			if returnType.Kind() == reflect.Ptr {
				normalized := strings.ToLower(method.Name)
				result[normalized] = returnType
			}
		}
	}

	return result
}

// getServiceTypeFromAPI uses reflection on IdsecAPI to find the service type
// by looking at the return type of API methods that match the service name pattern
func getServiceTypeFromAPI(serviceName string) reflect.Type {
	// Normalize: remove hyphens and lowercase to match against the pre-built map
	// e.g., "sia-workspaces-target-sets" -> "siaworkspacestargetsets"
	normalized := strings.ToLower(strings.ReplaceAll(serviceName, "-", ""))
	return serviceTypeMap[normalized]
}

// validateCLIActionDefinition validates methods for an action definition's schema map.
// Note: This function does NOT recurse into subactions because subactions belong
// to different services (subservices) which are tested separately. Only the actions
// in the current definition's schema map are validated against the current service type.
func validateCLIActionDefinition(t *testing.T, serviceType reflect.Type, schemas map[string]interface{}) {
	// Validate methods for all actions in this definition's schema map
	for actionName := range schemas {
		t.Run(actionName, func(t *testing.T) {
			// Convert action name to method name using the production transformation
			methodName := common.ConvertKeyToPascalCase(actionName)

			// Check if method exists on the service
			method, exists := serviceType.MethodByName(methodName)
			if !exists {
				t.Errorf("Method '%s' (from action '%s') does not exist on service type %s",
					methodName, actionName, serviceType.String())
				return
			}

			// Verify method is actually callable (exported)
			if method.PkgPath != "" {
				t.Errorf("Method '%s' (from action '%s') is not exported on service type %s",
					methodName, actionName, serviceType.String())
			}
		})
	}

	// Note: Subactions are NOT validated here because they belong to different services
	// (e.g., policy-cloudaccess, policy-db are separate services from policy).
	// Each service is validated independently via AllServiceConfigs iteration.
}

// TestAllCLIActionMethodSignatures validates that all CLI action methods have correct signatures
// for reflection-based invocation.
//
// This test validates that each CLI action method can be safely invoked via reflection by checking:
//  1. Parameter count matches schema presence (0 params if no schema, 1 param if schema exists)
//  2. Parameter type matches the schema type defined in ActionToSchemaMap
//  3. Method returns at least one value (the error)
//  4. Last return value is of type error for proper error handling
//
// This prevents runtime panics from reflection.Call() due to signature mismatches and ensures
// that the CLI execution framework can properly invoke methods and handle errors.
//
// The validation is critical because the CLI uses reflection to dynamically invoke methods:
//   - actionMethod.Call(actionArgs) where actionArgs contains the schema struct
//   - Result processing expects error as the last return value
func TestAllCLIActionMethodSignatures(t *testing.T) {
	// Get all registered service configurations
	allConfigs := services.AllServiceConfigs()

	if len(allConfigs) == 0 {
		t.Skip("No service configurations registered")
	}

	for _, config := range allConfigs {
		t.Run(config.ServiceName, func(t *testing.T) {
			validateCLIActionMethodSignatures(t, config)
		})
	}
}

// validateCLIActionMethodSignatures validates method signatures for all CLI actions in a service
func validateCLIActionMethodSignatures(t *testing.T, config services.IdsecServiceConfig) {
	// Extract action schemas from the service config
	if len(config.ActionSchemas) == 0 {
		t.Skip("No action schemas defined for this service")
		return
	}

	// Get the service type using IdsecAPI reflection
	serviceType := getServiceTypeFromAPI(config.ServiceName)
	if serviceType == nil {
		t.Skipf("Could not determine service type for %s", config.ServiceName)
		return
	}

	validateCLIActionDefinitionSignatures(t, serviceType, config.ActionSchemas)
}

// validateCLIActionDefinitionSignatures validates method signatures for an action definition's schema map
func validateCLIActionDefinitionSignatures(t *testing.T, serviceType reflect.Type, schemas map[string]interface{}) {
	// Validate signatures for all actions in this definition's schema map
	for actionName, schemaInterface := range schemas {
		t.Run(actionName, func(t *testing.T) {
			// Convert action name to method name using the production transformation
			methodName := common.ConvertKeyToPascalCase(actionName)

			// Get the method
			method, exists := serviceType.MethodByName(methodName)
			if !exists {
				// Method existence is already tested in TestAllCLIActionMethodsExist
				// Skip signature validation if method doesn't exist
				t.Skipf("Method '%s' does not exist (will be caught by TestAllCLIActionMethodsExist)", methodName)
				return
			}

			methodType := method.Type

			// Validate parameter count and types
			// Method signature should be: func (receiver) MethodName(schema *SchemaType) (result, error)
			// Or for methods without schema: func (receiver) MethodName() (result, error)
			//
			// methodType.NumIn() includes the receiver, so:
			// - For methods with schema: NumIn() == 2 (receiver + schema parameter)
			// - For methods without schema: NumIn() == 1 (receiver only)

			hasSchema := schemaInterface != nil
			expectedNumIn := 1 // receiver only
			if hasSchema {
				expectedNumIn = 2 // receiver + schema parameter
			}

			if methodType.NumIn() != expectedNumIn {
				if hasSchema {
					t.Errorf("Method '%s' has incorrect parameter count: got %d parameters (excluding receiver), want 1 (schema parameter)",
						methodName, methodType.NumIn()-1)
				} else {
					t.Errorf("Method '%s' has incorrect parameter count: got %d parameters (excluding receiver), want 0 (no schema)",
						methodName, methodType.NumIn()-1)
				}
				return
			}

			// If schema exists, validate parameter type matches schema type
			if hasSchema {
				schemaType := reflect.TypeOf(schemaInterface)
				// Parameter is at index 1 (index 0 is the receiver)
				paramType := methodType.In(1)

				// Both should be pointer types or both should be value types
				if schemaType != paramType {
					t.Errorf("Method '%s' parameter type mismatch: method expects %s, schema map defines %s",
						methodName, paramType.String(), schemaType.String())
					return
				}
			}

			// Validate return values
			// Method should return at least one value (error)
			// All CLI action methods must return error as the last value for consistent error handling.
			// Common patterns:
			// - func() error
			// - func() (result, error)
			// - func(*Schema) error
			// - func(*Schema) (result, error)
			//
			// Even simple getters should return error for:
			// - Consistency across all CLI actions
			// - Future-proofing (method may need to validate/fail later)
			// - Clear contract with the CLI framework
			if methodType.NumOut() < 1 {
				t.Errorf("Method '%s' must return at least one value (error), but returns %d values",
					methodName, methodType.NumOut())
				return
			}

			// Last return value must be error type
			lastReturnType := methodType.Out(methodType.NumOut() - 1)
			errorInterface := reflect.TypeOf((*error)(nil)).Elem()

			if !lastReturnType.Implements(errorInterface) {
				t.Errorf("Method '%s' last return value must be error, got %s. All CLI action methods must return error for consistent error handling.",
					methodName, lastReturnType.String())
				return
			}

			// If there are multiple return values, first ones should not be error type
			// (to avoid confusion like func() (error, error))
			if methodType.NumOut() > 1 {
				for i := 0; i < methodType.NumOut()-1; i++ {
					returnType := methodType.Out(i)
					if returnType.Implements(errorInterface) {
						t.Errorf("Method '%s' return value at index %d should not be error type (only last return should be error), got %s",
							methodName, i, returnType.String())
					}
				}
			}
		})
	}

	// Note: Subactions are NOT validated here because they belong to different services.
	// Each service is validated independently via AllServiceConfigs iteration.
}
