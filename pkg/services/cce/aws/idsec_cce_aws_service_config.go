package aws

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	awsactions "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/actions"
)

// ServiceConfig is the configuration for the CCE AWS service.
var ServiceConfig = services.IdsecServiceConfig{
	ServiceName:                "cce-aws",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
	ActionsConfigurations: map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition{
		actions.IdsecServiceActionTypeTerraformResource: {
			awsactions.TerraformActionAccountResource,
			awsactions.TerraformActionOrganizationAccountResource,
			awsactions.TerraformActionOrganizationResource,
		},
		actions.IdsecServiceActionTypeTerraformDataSource: {
			awsactions.TerraformActionWorkspacesDataSource,
			awsactions.TerraformActionAccountDataSource,
			awsactions.TerraformActionTenantServiceDetailsDataSource,
			awsactions.TerraformActionOrganizationDataSource,
		},
	},
}

// ServiceGenerator is the function that creates a new instance of the CCE AWS service.
var ServiceGenerator = NewIdsecCCEAWSService

// Module init, registers the service configuration.
func init() {
	err := services.Register(ServiceConfig, false)
	if err != nil {
		panic(err)
	}
}
