package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	certificatesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates/models"
)

// TerraformActionCertificateResource is a struct that defines the SIA certificate resource action for the Idsec service for Terraform.
var TerraformActionCertificateResource = &actions.IdsecServiceTerraformResourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-certificate",
			ActionDescription: "SIA Certificate resource, manages a certificate in SIA that is used for connections.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &certificatesmodels.IdsecSIACertificatesCertificate{},
	},
	SupportedOperations: []actions.IdsecServiceActionOperation{
		actions.CreateOperation,
		actions.ReadOperation,
		actions.UpdateOperation,
		actions.DeleteOperation,
		actions.StateOperation,
	},
	ActionsMappings: map[actions.IdsecServiceActionOperation]string{
		actions.CreateOperation: "add-certificate",
		actions.ReadOperation:   "certificate",
		actions.UpdateOperation: "update-certificate",
		actions.DeleteOperation: "delete-certificate",
	},
}

// TerraformActionCertificateDataSource is a struct that defines the sia certificate data source action for the Idsec service for Terraform.
var TerraformActionCertificateDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sia-certificate",
			ActionDescription: "SIA certificate source, reads certificate information.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &certificatesmodels.IdsecSIACertificatesCertificate{},
		ExtraRequiredAttributes: []string{
			"certificate_id",
		},
	},
	DataSourceAction: "certificate",
}
