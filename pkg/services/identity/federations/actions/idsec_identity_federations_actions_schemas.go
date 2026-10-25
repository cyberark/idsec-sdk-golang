// Package actions defines the CLI and Terraform action schemas for the IDSEC Identity federations service.
package actions

import (
	federationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/federations/models"
)

// ActionToSchemaMap defines the mapping between Federation action names and their
// corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &federationsmodels.IdsecIdentityCreateFederation{},
	"update":  &federationsmodels.IdsecIdentityUpdateFederation{},
	"delete":  &federationsmodels.IdsecIdentityDeleteFederation{},
	"get":     &federationsmodels.IdsecIdentityGetFederation{},
	"list":    nil,
	"list-by": &federationsmodels.IdsecIdentityFederationFilters{},

	"add-global-group-mapping":    &federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{},
	"get-global-group-mapping":    &federationsmodels.IdsecIdentityGetFederationGlobalGroupMapping{},
	"remove-global-group-mapping": &federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping{},
	"list-global-group-mappings":  nil,
}
