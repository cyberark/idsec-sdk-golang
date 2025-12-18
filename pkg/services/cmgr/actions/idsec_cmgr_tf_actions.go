package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	cmgrmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/models"
)

// TerraformActionNetworkResource is a struct that defines the CMGR action for the Idsec service for Terraform.
var TerraformActionNetworkResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "cmgr-network",
			ActionDescription: "The Connector Management service network resource that is used to manage networks associated with pools.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &cmgrmodels.IdsecCmgrNetwork{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-network",
		actions.ReadOperation:   "network",
		actions.UpdateOperation: "update-network",
		actions.DeleteOperation: "delete-network",
	},
}

// TerraformActionPoolResource is a struct that defines the CMGR pool action for the Idsec service for Terraform.
var TerraformActionPoolResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "cmgr-pool",
			ActionDescription: "The Connector Management service pool resource that manages the pool of Secure Infrastructure Access (SIA) and system connectors.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{
			"assigned_network_ids",
		},
		StateSchema: &cmgrmodels.IdsecCmgrPool{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-pool",
		actions.ReadOperation:   "pool",
		actions.UpdateOperation: "update-pool",
		actions.DeleteOperation: "delete-pool",
	},
}

// TerraformActionPoolIdentifierResource is a struct that defines the CMGR pool identifier action for the Idsec service for Terraform.
var TerraformActionPoolIdentifierResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "cmgr-pool-identifier",
			ActionDescription: "The Connector Management service pool identifier resource that is associated with a pool and is used to identify the pool in a simplified manner. It is not identified using only the network name",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{
			"pool_id",
			"type",
			"value",
		},
		StateSchema: &cmgrmodels.IdsecCmgrPoolIdentifier{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-pool-identifier",
		actions.ReadOperation:   "pool-identifier",
		actions.UpdateOperation: "update-pool-identifier",
		actions.DeleteOperation: "delete-pool-identifier",
	},
}

// TerraformActionNetworkDataSource is a struct that defines the CMGR network action for the Idsec service for Terraform.
var TerraformActionNetworkDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "cmgr-network",
			ActionDescription: "The Connector Management service network data source. It reads the network information and metadata and is based on the ID of the network.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{
			"network_id",
		},
		StateSchema: &cmgrmodels.IdsecCmgrNetwork{},
	},
	DataSourceAction: "network",
}

// TerraformActionPoolDataSource is a struct that defines the CMGR pool action for the Idsec service for Terraform.
var TerraformActionPoolDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "cmgr-pool",
			ActionDescription: "The Connector Management service pool data source. It reads the pool information and metadata and is based on the ID of the pool.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{
			"pool_id",
		},
		StateSchema: &cmgrmodels.IdsecCmgrPool{},
	},
	DataSourceAction: "pool",
}

// TerraformActionPoolIdentifierDataSource is a struct that defines the CMGR pool identifier action for the Idsec service for Terraform.
var TerraformActionPoolIdentifierDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "cmgr-pool-identifier",
			ActionDescription: "The Connector Management service pool data source. It reads the pool information and metadata and is based on the ID of the pool.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		ExtraRequiredAttributes: []string{
			"pool_id",
			"identifier_id",
		},
		StateSchema: &cmgrmodels.IdsecCmgrPoolIdentifier{},
	},
	DataSourceAction: "pool-identifier",
}
