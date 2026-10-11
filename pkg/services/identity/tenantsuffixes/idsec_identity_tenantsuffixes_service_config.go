// Package tenantsuffixes provides the Identity tenant suffixes service, which creates, reads, lists, renames and deletes tenant login suffixes.
package tenantsuffixes

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/tenantsuffixes/actions"
)

// ServiceConfig is the configuration for the identity-tenant-suffixes service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "identity-tenant-suffixes",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of the IdsecIdentityTenantSuffixesService.
var ServiceGenerator = NewIdsecIdentityTenantSuffixesService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
