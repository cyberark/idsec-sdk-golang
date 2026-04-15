package cmgr

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// ServiceConfig is the configuration for the connector management service.
// CLI actions are defined in the idsec-cli-golang repository.
// Terraform actions are defined in the child service configs (networks, pools, etc.).
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "cmgr",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
}

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, true)
	if err != nil {
		panic(err)
	}
}
