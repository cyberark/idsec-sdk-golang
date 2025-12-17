package accounts

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	pcloudaccountsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/actions"
)

// ServiceConfig is the configuration for the pcloud accounts service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "pcloud-accounts",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeCLI: {
			pcloudaccountsactions.CLIAction,
		},
		actions.IdsecServiceActionTypeTerraformResource: {
			pcloudaccountsactions.TerraformActionAccountResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			pcloudaccountsactions.TerraformActionAccountDataSource,
		},
	},
}

// ServiceGenerator is the function that generates a new instance of the IdsecPCloudAccountsService.
var ServiceGenerator = NewIdsecPCloudAccountsService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
