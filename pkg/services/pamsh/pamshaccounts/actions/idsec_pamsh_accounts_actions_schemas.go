package actions

import accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"

// ActionToSchemaMap maps Terraform-style action names to schema types for PAM self-hosted accounts (PAS REST wire shape).
var ActionToSchemaMap = map[string]interface{}{
	"create": &accountsmodels.IdsecPamshAddAccount{},
	"update": &accountsmodels.IdsecPamshUpdateAccount{},
	"delete": &accountsmodels.IdsecPamshDeleteAccount{},
	"get":    &accountsmodels.IdsecPamshGetAccount{},
}
