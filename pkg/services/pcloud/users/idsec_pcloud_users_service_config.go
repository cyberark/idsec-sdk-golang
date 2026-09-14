package users

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/users/actions"
)

// ServiceConfig is the configuration for the pcloud users service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pcloud-users",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that generates a new instance of IdsecPCloudUsersService.
var ServiceGenerator = NewIdsecPCloudUsersService

// Module init registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
