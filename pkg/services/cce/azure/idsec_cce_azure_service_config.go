package azure

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// ServiceConfig is the configuration for the CCE Azure service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "cce-azure",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeTerraformResource: {
			// azureactions.TerraformActionEntraResource,
			// azureactions.TerraformActionManagementGroupResource,
			// azureactions.TerraformActionSubscriptionResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			// azureactions.TerraformActionEntraDataSource,
			// azureactions.TerraformActionManagementGroupDataSource,
			// azureactions.TerraformActionSubscriptionDataSource,
			// azureactions.TerraformActionWorkspacesDataSource,
			// azureactions.TerraformActionIdentityParamsDataSource,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the CCE Azure service.
var ServiceGenerator = NewIdsecCCEAzureService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
