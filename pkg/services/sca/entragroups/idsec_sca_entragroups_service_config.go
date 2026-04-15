package entragroups

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/entragroups/actions"
)

// ServiceConfig is the configuration for the SCA Entra Groups service.
//
// Registered as a non-top-level service (false). The CLI action tree is owned
// by the parent "sca" service in the idsec-cli-golang repository.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sca-entragroups",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator creates a new IdsecSCAEntraGroupsService instance.
var ServiceGenerator = NewIdsecSCAEntraGroupsService

// init registers the sca-entragroups service configuration at package load time.
// Registered with false (not top-level) — the CLI tree is rooted at the parent "sca" service.
func init() {
	if err := services.Register(ServiceConfig, false); err != nil {
		panic(err)
	}
}
