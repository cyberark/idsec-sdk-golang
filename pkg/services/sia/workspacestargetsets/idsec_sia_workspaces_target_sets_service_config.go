package targetsets

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacestargetsets/actions"
)

// ServiceConfig is the configuration for the SIA target sets workspace service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sia-workspaces-target-sets",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of the IdsecSIAWorkspacesTargetSetsService.
var ServiceGenerator = NewIdsecSIAWorkspacesTargetSetsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
