package actions

import dbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/db/models"

// ActionToSchemaMap is a map that defines the mapping between db action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"psql":                      &dbmodels.IdsecSIADBPsqlExecution{},
	"mysql":                     &dbmodels.IdsecSIADBMysqlExecution{},
	"sqlcmd":                    &dbmodels.IdsecSIADBSqlcmdExecution{},
	"generate-oracle-tnsnames":  &dbmodels.IdsecSIADBOracleGenerateAssets{},
	"generate-proxy-full-chain": &dbmodels.IdsecSIADBProxyFullChainGenerateAssets{},
}
