package actions

import secretsdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/db/models"

// ActionToSchemaMap is a map that defines the mapping between Secrets DB action names and their corresponding schema types.
// This map includes both secrets and strong account actions for CLI usage.
var ActionToSchemaMap = map[string]interface{}{
	// Secrets actions
	"add-secret":      &secretsdbmodels.IdsecSIADBAddSecret{},
	"update-secret":   &secretsdbmodels.IdsecSIADBUpdateSecret{},
	"delete-secret":   &secretsdbmodels.IdsecSIADBDeleteSecret{},
	"list-secrets":    nil,
	"list-secrets-by": &secretsdbmodels.IdsecSIADBSecretsFilter{},
	"enable-secret":   &secretsdbmodels.IdsecSIADBEnableSecret{},
	"disable-secret":  &secretsdbmodels.IdsecSIADBDisableSecret{},
	"secret":          &secretsdbmodels.IdsecSIADBGetSecret{},
	"secrets-stats":   nil,
	// Strong Account actions (for CLI)
	"add-strong-account":    &secretsdbmodels.IdsecSIADBAddStrongAccount{},
	"update-strong-account": &secretsdbmodels.IdsecSIADBUpdateStrongAccount{},
	"delete-strong-account": &secretsdbmodels.IdsecSIADBDeleteStrongAccount{},
	"strong-account":        &secretsdbmodels.IdsecSIADBGetStrongAccount{},
	"list-strong-accounts":  &secretsdbmodels.IdsecSIADBListStrongAccounts{},
}

// StrongAccountActionToSchemaMap is a map that defines the mapping between Strong Account DB action names and their corresponding schema types.
// This map is used for Terraform
var StrongAccountActionToSchemaMap = map[string]interface{}{
	"add-strong-account":    &secretsdbmodels.IdsecSIADBAddStrongAccount{},
	"update-strong-account": &secretsdbmodels.IdsecSIADBUpdateStrongAccount{},
	"delete-strong-account": &secretsdbmodels.IdsecSIADBDeleteStrongAccount{},
	"strong-account":        &secretsdbmodels.IdsecSIADBGetStrongAccount{},
	"list-strong-accounts":  &secretsdbmodels.IdsecSIADBListStrongAccounts{},
}
