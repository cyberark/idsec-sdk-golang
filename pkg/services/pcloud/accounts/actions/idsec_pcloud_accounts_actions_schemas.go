package actions

import accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"

// ActionToSchemaMap is a map that defines the mapping between Idsec Privilege Cloud action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create":                      &accountsmodels.IdsecPCloudAddAccount{},
	"update":                      &accountsmodels.IdsecPCloudUpdateAccount{},
	"delete":                      &accountsmodels.IdsecPCloudDeleteAccount{},
	"get":                         &accountsmodels.IdsecPCloudGetAccount{},
	"get-credentials":             &accountsmodels.IdsecPCloudGetAccountCredentials{},
	"list":                        nil,
	"list-by":                     &accountsmodels.IdsecPCloudAccountsFilter{},
	"list-secret-versions":        &accountsmodels.IdsecPCloudListAccountSecretVersions{},
	"generate-credentials":        &accountsmodels.IdsecPCloudGenerateAccountCredentials{},
	"verify-credentials":          &accountsmodels.IdsecPCloudVerifyAccountCredentials{},
	"change-credentials":          &accountsmodels.IdsecPCloudChangeAccountCredentials{},
	"set-next-credentials":        &accountsmodels.IdsecPCloudSetAccountNextCredentials{},
	"update-credentials-in-vault": &accountsmodels.IdsecPCloudUpdateAccountCredentialsInVault{},
	"reconcile-credentials":       &accountsmodels.IdsecPCloudReconcileAccountCredentials{},
	"link":                        &accountsmodels.IdsecPCloudLinkAccount{},
	"unlink":                      &accountsmodels.IdsecPCloudUnlinkAccount{},
	"stats":                       nil,
}
