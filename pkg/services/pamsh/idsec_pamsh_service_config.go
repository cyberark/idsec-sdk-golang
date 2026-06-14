package pamsh

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// ServiceConfig is the umbrella configuration for PAM self-hosted (pamsh) services.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pamsh",
	RequiredAuthenticatorNames: []string{"pvwa"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	Enabled:                    enabled(false),
	ActionSchemas:              nil,
}

func enabled(b bool) *bool {
	return &b
}

func init() {
	if err := services.Register(ServiceConfig, true); err != nil {
		panic(err)
	}
}
