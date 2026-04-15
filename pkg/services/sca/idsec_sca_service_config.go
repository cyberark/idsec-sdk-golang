package sca

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/actions"
)

// ServiceConfig defines the service configuration for the standalone SCA service.
// CLI and Terraform actions have been moved to their respective repositories.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sca",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator returns a new IdsecSCAService instance. Provided for consistency with other service configs.
var ServiceGenerator = NewIdsecSCAService

// init registers the standalone SCA service configuration at package load time.
func init() {
	if err := services.Register(ServiceConfig, true); err != nil {
		panic(err)
	}
}
