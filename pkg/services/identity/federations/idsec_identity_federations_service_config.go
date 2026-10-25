// Package federations provides the IDSEC Identity federations service, which manages SAML 2.0
// and OIDC identity provider federations and their global group mappings.
package federations

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/federations/actions"
)

// ServiceConfig is the configuration for the identity-federations service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity-federations",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of the IdsecIdentityFederationsService.
var ServiceGenerator = NewIdsecIdentityFederationsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
