// Package actions provides the action schema map for the Identity tenant suffixes service.
package actions

import (
	tenantsuffixesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/tenantsuffixes/models"
)

// ActionToSchemaMap defines the mapping between TenantSuffix action names and their
// corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{},
	"delete":  &tenantsuffixesmodels.IdsecIdentityDeleteTenantSuffix{},
	"get":     &tenantsuffixesmodels.IdsecIdentityGetTenantSuffix{},
	"update":  &tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{},
	"list":    nil,
	"list-by": &tenantsuffixesmodels.IdsecIdentityTenantSuffixFilters{},
}
