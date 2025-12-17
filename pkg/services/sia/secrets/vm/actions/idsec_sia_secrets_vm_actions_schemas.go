package actions

import secretsvmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secrets/vm/models"

// ActionToSchemaMap is a map that defines the mapping between Secrets VM action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"add-secret":      &secretsvmmodels.IdsecSIAVMAddSecret{},
	"change-secret":   &secretsvmmodels.IdsecSIAVMChangeSecret{},
	"delete-secret":   &secretsvmmodels.IdsecSIAVMDeleteSecret{},
	"list-secrets":    nil,
	"list-secrets-by": &secretsvmmodels.IdsecSIAVMSecretsFilter{},
	"secret":          &secretsvmmodels.IdsecSIAVMGetSecret{},
	"secrets-stats":   nil,
}
