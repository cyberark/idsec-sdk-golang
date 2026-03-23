package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"
)

// TerraformActionTenantSuffixesDataSource is a struct that defines the tenant suffixes data source for the Idsec service for Terraform.
var TerraformActionTenantSuffixesDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "identity-tenant-suffixes",
			ActionDescription: "The Identity service tenant suffixes data source. It reads the tenant suffixes information.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &directoriesmodels.IdsecIdentityTenantSuffixes{},
	},
	DataSourceAction: "tenant-suffixes",
}
