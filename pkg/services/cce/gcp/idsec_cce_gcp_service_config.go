package gcp

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/actions"
)

func boolPtr(b bool) *bool { return &b }

// ServiceConfig is the configuration for the CCE GCP service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "cce-gcp",
	Enabled:                    boolPtr(false),
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that creates a new instance of the CCE GCP service.
var ServiceGenerator = NewIdsecCCEGCPService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
