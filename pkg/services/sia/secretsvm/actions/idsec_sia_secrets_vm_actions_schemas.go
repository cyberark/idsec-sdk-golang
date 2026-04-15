package actions

import secretsvmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsvm/models"

// ActionToSchemaMap is a map that defines the mapping between Secrets VM action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &secretsvmmodels.IdsecSIAVMAddSecret{},
	"change":  &secretsvmmodels.IdsecSIAVMChangeSecret{},
	"delete":  &secretsvmmodels.IdsecSIAVMDeleteSecret{},
	"list":    nil,
	"list-by": &secretsvmmodels.IdsecSIAVMSecretsFilter{},
	"get":     &secretsvmmodels.IdsecSIAVMGetSecret{},
	"stats":   nil,
}
