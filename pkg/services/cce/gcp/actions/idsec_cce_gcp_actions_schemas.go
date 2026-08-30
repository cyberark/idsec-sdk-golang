package actions

import (
	gcpmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/models"
)

// ActionToSchemaMap is a map that defines the mapping between CCE GCP action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	// Identity Params data source
	"tf-identity-params": &gcpmodels.TfIdsecCCEGCPGetIdentityParams{},
	// Workspaces data source
	"tf-workspaces": &gcpmodels.TfIdsecCCEGCPGetWorkspacesTerraform{},
	// Project actions
	"tf-project": &gcpmodels.TfIdsecCCEGCPGetProject{},
	// Organization actions
	"tf-organization": &gcpmodels.TfIdsecCCEGCPGetOrganization{},
}
