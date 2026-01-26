package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	platformsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms/models"
)

// TerraformActionTargetPlatformResource is a struct that defines the Privilege Cloud target platform resource action for the Idsec service for Terraform.
var TerraformActionTargetPlatformResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-target-platform",
			ActionDescription: "Privilege Cloud target platform resource, manages the import of Privilege Cloud target platforms.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &platformsmodels.IdsecPCloudTargetPlatform{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "import-target-platform",
		actions.ReadOperation:   "target-platform",
		actions.DeleteOperation: "delete-target-platform",
	},
}

// TerraformActionTargetPlatformDataSource is a struct that defines the Privilege Cloud target platform data source action for the Idsec service for Terraform.
var TerraformActionTargetPlatformDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "pcloud-target-platform",
			ActionDescription: "Privilege Cloud target platform data source, reads target platform information and metadata, based on the platform ID.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{
			"platform_id",
		},
		StateSchema: &platformsmodels.IdsecPCloudTargetPlatform{},
	},
	DataSourceAction: "target-platform",
}
