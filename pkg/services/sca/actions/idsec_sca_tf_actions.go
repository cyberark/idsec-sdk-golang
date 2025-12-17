package actions

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

// TerraformActionSCADiscoveryDataSource defines the standalone SCA discovery Terraform data source.
//
// It exposes the sca-discovery data source that starts a discovery job and returns
// its initial response (including job_id and already_running fields).
//
// Example Terraform (pseudo):
//
//	data "idsec_sca_discovery" "example" {
//	  csp             = var.csp
//	  organization_id = var.org_id
//	  account_info = {
//	    id          = var.account_id
//	    new_account = var.new_account
//	  }
//	}
//
// The state schema maps to IdsecSCADiscoveryResponse. No resource (CRUD) or policy
// related data sources are exposed in the standalone SCA service.
var TerraformActionSCADiscoveryDataSource = &actions.IdsecServiceTerraformDataSourceActionDefinition{
	IdsecServiceBaseTerraformActionDefinition: actions.IdsecServiceBaseTerraformActionDefinition{
		IdsecServiceBaseActionDefinition: actions.IdsecServiceBaseActionDefinition{
			ActionName:        "sca-discovery",
			ActionDescription: "Standalone SCA Discovery Data Source.",
			ActionVersion:     1,
			Schemas:           ActionToSchemaMap,
		},
		StateSchema: &scamodels.IdsecSCADiscoveryResponse{},
	},
	DataSourceAction: "discovery",
}
