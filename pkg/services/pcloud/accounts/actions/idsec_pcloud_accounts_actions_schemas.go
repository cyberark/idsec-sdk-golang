package actions

import accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"

// ActionToSchemaMap is a map that defines the mapping between Idsec PCloud action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"add-account":                         &accountsmodels.IdsecPCloudAddAccount{},
	"update-account":                      &accountsmodels.IdsecPCloudUpdateAccount{},
	"delete-account":                      &accountsmodels.IdsecPCloudDeleteAccount{},
	"account":                             &accountsmodels.IdsecPCloudGetAccount{},
	"account-credentials":                 &accountsmodels.IdsecPCloudGetAccountCredentials{},
	"list-accounts":                       nil,
	"list-accounts-by":                    &accountsmodels.IdsecPCloudAccountsFilter{},
	"list-account-secret-versions":        &accountsmodels.IdsecPCloudListAccountSecretVersions{},
	"generate-account-credentials":        &accountsmodels.IdsecPCloudGenerateAccountCredentials{},
	"verify-account-credentials":          &accountsmodels.IdsecPCloudVerifyAccountCredentials{},
	"change-account-credentials":          &accountsmodels.IdsecPCloudChangeAccountCredentials{},
	"set-account-next-credentials":        &accountsmodels.IdsecPCloudSetAccountNextCredentials{},
	"update-account-credentials-in-vault": &accountsmodels.IdsecPCloudUpdateAccountCredentialsInVault{},
	"reconcile-account-credentials":       &accountsmodels.IdsecPCloudReconcileAccountCredentials{},
	"link-account":                        &accountsmodels.IdsecPCloudLinkAccount{},
	"unlink-account":                      &accountsmodels.IdsecPCloudUnlinkAccount{},
	"accounts-stats":                      nil,
}
