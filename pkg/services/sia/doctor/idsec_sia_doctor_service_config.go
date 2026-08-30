package doctor

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/doctor/actions"
)

// ServiceConfig is the configuration for IdsecSIADoctorService.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-doctor",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator creates a new IdsecSIADoctorService from variadic authenticators.
var ServiceGenerator = NewIdsecSIADoctorService

// init registers the service configuration with the global service registry.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
