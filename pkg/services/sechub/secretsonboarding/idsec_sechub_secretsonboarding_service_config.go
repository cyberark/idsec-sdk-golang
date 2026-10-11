package secretsonboarding

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretsonboarding/actions"
)

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool { return &b }

// ServiceConfig is the configuration for the Secrets Hub secret onboarding service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "sechub-secretsonboarding",
	Enabled:                    boolPtr(false), // Service is disabled in production
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations:      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{},
	ActionSchemas:              svcactions.ActionToSchemaMap,
}

// ServiceGenerator is the function that creates a new instance of the SecHub secret onboarding service.
var ServiceGenerator = NewIdsecSecHubSecretOnboardingService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
