package actions

import secretsdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsdb/models"

// ActionToSchemaMap is a map that defines the mapping between Secrets DB action names and their corresponding schema types.
// Note: This resource uses the legacy secrets API. For strong accounts, use the db-strong-accounts resource instead.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &secretsdbmodels.IdsecSIADBAddSecret{},
	"update":  &secretsdbmodels.IdsecSIADBUpdateSecret{},
	"delete":  &secretsdbmodels.IdsecSIADBDeleteSecret{},
	"list":    nil,
	"list-by": &secretsdbmodels.IdsecSIADBSecretsFilter{},
	"enable":  &secretsdbmodels.IdsecSIADBEnableSecret{},
	"disable": &secretsdbmodels.IdsecSIADBDisableSecret{},
	"get":     &secretsdbmodels.IdsecSIADBGetSecret{},
	"stats":   nil,
}
