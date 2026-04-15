package actions

import dbstrongaccountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/dbstrongaccounts/models"

// ActionToSchemaMap is a map that defines the mapping between Strong Account DB action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":  &dbstrongaccountsmodels.IdsecSIADBAddStrongAccount{},
	"update":  &dbstrongaccountsmodels.IdsecSIADBUpdateStrongAccount{},
	"delete":  &dbstrongaccountsmodels.IdsecSIADBDeleteStrongAccount{},
	"get":     &dbstrongaccountsmodels.IdsecSIADBGetStrongAccount{},
	"list":    nil,
	"list-by": &dbstrongaccountsmodels.IdsecSIADBStrongAccountsFilter{},
}
